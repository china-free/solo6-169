import threading
import time
import socket
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

import psutil

from .process_tracker import ProcessTracker, ConnectionTuple
from .capture_engine import (
    CaptureEngine,
    RawPacketMeta,
    get_best_engine,
    SubprocessDumpcapEngine
)


GRACE_PERIOD_SECONDS = 10.0
CONNECTION_POLL_INTERVAL = 1.0
BPF_REFRESH_INTERVAL = 5.0


class PacketRecord:
    def __init__(
        self,
        timestamp: datetime,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        payload: bytes,
        direction: str = "outbound",
        connection_key: Optional[Tuple[str, str, int, str, int]] = None
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.payload = payload
        self.direction = direction
        self.connection_key = connection_key

    def to_dict(self) -> Dict[str, Any]:
        payload_preview = ""
        if self.payload:
            try:
                payload_preview = self.payload.decode('utf-8', errors='replace')[:2048]
            except Exception:
                payload_preview = self.payload[:256].hex()
        return {
            'timestamp': self.timestamp.isoformat(),
            'src': f"{self.src_ip}:{self.src_port}",
            'dst': f"{self.dst_ip}:{self.dst_port}",
            'protocol': self.protocol,
            'direction': self.direction,
            'payload_preview': payload_preview,
            'payload_bytes': len(self.payload)
        }


class _ConnectionState:
    __slots__ = ('first_seen', 'last_seen', 'is_active', 'removed_at')

    def __init__(self):
        now = datetime.now()
        self.first_seen: datetime = now
        self.last_seen: datetime = now
        self.is_active: bool = True
        self.removed_at: Optional[datetime] = None

    def touch(self):
        self.last_seen = datetime.now()
        self.is_active = True
        self.removed_at = None

    def mark_removed(self):
        if self.is_active:
            self.is_active = False
            self.removed_at = datetime.now()

    def is_within_grace_period(self, grace_seconds: float = GRACE_PERIOD_SECONDS) -> bool:
        if self.is_active:
            return True
        if self.removed_at is None:
            return False
        return (datetime.now() - self.removed_at).total_seconds() <= grace_seconds


class ConnectionTracker:
    def __init__(self, grace_seconds: float = GRACE_PERIOD_SECONDS):
        self._states: Dict[Tuple[str, str, int, str, int], _ConnectionState] = {}
        self._grace_seconds = grace_seconds
        self._lock = threading.Lock()
        self._changed = threading.Event()

    def sync_from(self, current_tuples: Set[ConnectionTuple]) -> bool:
        changed = False
        current_keys = {ct.key for ct in current_tuples}
        with self._lock:
            existing_keys = set(self._states.keys())
            new_keys = current_keys - existing_keys
            removed_keys = existing_keys - current_keys
            if new_keys or removed_keys:
                changed = True
                self._changed.set()
            for key in current_keys:
                if key in self._states:
                    self._states[key].touch()
                else:
                    self._states[key] = _ConnectionState()
            for key in removed_keys:
                if self._states[key].is_active:
                    self._states[key].mark_removed()
        return changed

    def contains(self, key: Tuple[str, str, int, str, int]) -> bool:
        with self._lock:
            state = self._states.get(key)
            if state is None:
                return False
            return state.is_within_grace_period(self._grace_seconds)

    def touch(self, key: Tuple[str, str, int, str, int]):
        with self._lock:
            state = self._states.get(key)
            if state:
                state.touch()

    def get_active_tuples(self) -> Set[ConnectionTuple]:
        tuples: Set[ConnectionTuple] = set()
        with self._lock:
            for (proto, lip, lport, rip, rport), state in self._states.items():
                if state.is_within_grace_period(self._grace_seconds):
                    tuples.add(ConnectionTuple(
                        protocol=proto,
                        local_ip=lip,
                        local_port=lport,
                        remote_ip=rip,
                        remote_port=rport
                    ))
        return tuples

    def get_active_ports(self) -> Set[int]:
        ports: Set[int] = set()
        with self._lock:
            for (proto, lip, lport, rip, rport), state in self._states.items():
                if state.is_within_grace_period(self._grace_seconds):
                    ports.add(lport)
        return ports

    def purge_expired(self):
        cutoff = datetime.now() - timedelta(seconds=self._grace_seconds * 3)
        with self._lock:
            expired = [
                k for k, s in self._states.items()
                if not s.is_active and s.removed_at and s.removed_at < cutoff
            ]
            for k in expired:
                del self._states[k]

    def active_count(self) -> int:
        with self._lock:
            return sum(
                1 for s in self._states.values()
                if s.is_within_grace_period(self._grace_seconds)
            )

    def clear_change_flag(self):
        self._changed.clear()

    def wait_for_change(self, timeout: float) -> bool:
        return self._changed.wait(timeout=timeout)


class TrafficCapture:
    def __init__(self, tracker: ProcessTracker):
        self.tracker = tracker
        self.packets: List[PacketRecord] = []
        self.remote_endpoints: Set[str] = set()
        self._stop_event = threading.Event()
        self._conn_poll_thread: Optional[threading.Thread] = None
        self._connection_tracker = ConnectionTracker(grace_seconds=GRACE_PERIOD_SECONDS)
        self._lock = threading.Lock()
        self._local_ip_cache: Set[str] = set()
        self._discarded_packets = 0
        self._accepted_packets = 0
        self._engine: Optional[CaptureEngine] = None
        self._engine_reqs: List[str] = []
        self._bpf_monitor_thread: Optional[threading.Thread] = None
        self._current_bpf = ""

    def _get_local_ips(self) -> Set[str]:
        ips = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(info[4][0])
        except Exception:
            pass
        ips.add('127.0.0.1')
        ips.add('::1')
        try:
            for nic, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(addr.address)
        except Exception:
            pass
        self._local_ip_cache = ips
        return ips

    def _refresh_connections(self) -> bool:
        try:
            tuples = self.tracker.get_active_connection_tuples(include_dying=False)
            changed = self._connection_tracker.sync_from(tuples)
            self._connection_tracker.purge_expired()
            return changed
        except Exception:
            return False

    def _conn_poll_worker(self):
        while not self._stop_event.is_set():
            self._refresh_connections()
            self._stop_event.wait(CONNECTION_POLL_INTERVAL)

    def _build_precise_bpf(self) -> str:
        if not self._engine:
            return ""
        active_tuples = self._connection_tracker.get_active_tuples()
        bpf = self._engine.build_bpf_filter(active_tuples)
        return bpf

    def _bpf_monitor_worker(self):
        while not self._stop_event.is_set():
            changed = self._connection_tracker.wait_for_change(timeout=BPF_REFRESH_INTERVAL)
            if self._stop_event.is_set():
                break
            if changed:
                self._connection_tracker.clear_change_flag()
                new_bpf = self._build_precise_bpf()
                if new_bpf and new_bpf != self._current_bpf:
                    self._current_bpf = new_bpf
                    print(f"[*] BPF 已更新（{self._connection_tracker.active_count()} 个活跃连接）")

    def _match_process_packet(self, meta: RawPacketMeta) -> Optional[PacketRecord]:
        local_ips = self._local_ip_cache or self._get_local_ips()
        direction = None
        ct = None

        if meta.src_ip in local_ips:
            direction = "outbound"
            ct = ConnectionTuple(
                protocol=meta.protocol,
                local_ip=meta.src_ip, local_port=meta.src_port,
                remote_ip=meta.dst_ip, remote_port=meta.dst_port
            )
        elif meta.dst_ip in local_ips:
            direction = "inbound"
            ct = ConnectionTuple(
                protocol=meta.protocol,
                local_ip=meta.dst_ip, local_port=meta.dst_port,
                remote_ip=meta.src_ip, remote_port=meta.src_port
            )
        else:
            return None

        if not self._connection_tracker.contains(ct.key):
            self._discarded_packets += 1
            return None

        self._connection_tracker.touch(ct.key)
        self._accepted_packets += 1

        return PacketRecord(
            timestamp=meta.timestamp,
            src_ip=meta.src_ip, src_port=meta.src_port,
            dst_ip=meta.dst_ip, dst_port=meta.dst_port,
            protocol=meta.protocol,
            payload=meta.payload,
            direction=direction,
            connection_key=ct.key
        )

    def _packet_callback(self, meta: RawPacketMeta):
        record = self._match_process_packet(meta)
        if record:
            with self._lock:
                self.packets.append(record)
                if record.direction == "outbound" and ProcessTracker.is_external_ip(record.dst_ip):
                    self.remote_endpoints.add(f"{record.dst_ip}:{record.dst_port}")

    def _post_hoc_validate(self):
        self._refresh_connections()
        valid_packets: List[PacketRecord] = []
        valid_endpoints: Set[str] = set()
        removed = 0

        with self._lock:
            for pkt in self.packets:
                if pkt.connection_key and self._connection_tracker.contains(pkt.connection_key):
                    valid_packets.append(pkt)
                    if pkt.direction == "outbound" and ProcessTracker.is_external_ip(pkt.dst_ip):
                        valid_endpoints.add(f"{pkt.dst_ip}:{pkt.dst_port}")
                else:
                    removed += 1
            self.packets = valid_packets
            self.remote_endpoints = valid_endpoints

        if removed > 0:
            print(f"[*] 后验清理：剔除 {removed} 个无法回溯到目标进程的可疑包")

    def start(self, duration: Optional[int] = None):
        self._engine, self._engine_reqs = get_best_engine()
        print(f"[*] 抓包引擎: {self._engine.name}")
        if self._engine.name == "scapy":
            print(f"[!] 警告：正在使用纯 Python scapy 引擎。强烈建议安装 tshark/dumpcap")
            print(f"[!] 以启用 C 级 BPF 过滤，大幅降低 CPU 占用。")

        self._get_local_ips()
        self._refresh_connections()

        if self._connection_tracker.active_count() == 0:
            print("[!] 警告：目标进程当前没有活跃网络连接，将持续监听新连接...")
        else:
            print(f"[*] 已锁定 {self._connection_tracker.active_count()} 个活跃连接（五元组精确追踪）")

        self._current_bpf = self._build_precise_bpf()
        if self._current_bpf:
            print(f"[*] BPF 过滤已下沉到内核/C 层（共 {len(self._current_bpf)} 字符）")

        self._stop_event.clear()

        self._conn_poll_thread = threading.Thread(target=self._conn_poll_worker, daemon=True)
        self._conn_poll_thread.start()

        self._bpf_monitor_thread = threading.Thread(target=self._bpf_monitor_worker, daemon=True)
        self._bpf_monitor_thread.start()

        self._engine.start(
            bpf_filter=self._current_bpf,
            callback=self._packet_callback,
            stop_event=self._stop_event
        )

        if duration:
            print(f"[*] 开始捕获流量，持续 {duration} 秒...")
            self._stop_event.wait(duration)
            self.stop()
        else:
            print("[*] 开始捕获流量，按 Ctrl+C 停止...")

    def stop(self):
        self._stop_event.set()
        if self._engine:
            self._engine.stop()
        if self._conn_poll_thread:
            self._conn_poll_thread.join(timeout=3)
        if self._bpf_monitor_thread:
            self._bpf_monitor_thread.join(timeout=3)
        self._post_hoc_validate()
        if self._discarded_packets > 0:
            print(f"[*] 过滤统计：接受 {self._accepted_packets} 个包，丢弃 {self._discarded_packets} 个不匹配五元组的包")

    def get_outbound_packets(self) -> List[PacketRecord]:
        with self._lock:
            return [p for p in self.packets if p.direction == "outbound"]

    def get_external_endpoints(self) -> Set[str]:
        return self.remote_endpoints.copy()

    def get_packets_with_payload(self) -> List[PacketRecord]:
        with self._lock:
            return [p for p in self.packets if p.payload and len(p.payload) > 0]
