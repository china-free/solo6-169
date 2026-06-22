import threading
import time
import socket
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import psutil

from .process_tracker import ProcessTracker, ConnectionTuple


GRACE_PERIOD_SECONDS = 10.0
CONNECTION_POLL_INTERVAL = 1.0


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

    def sync_from(self, current_tuples: Set[ConnectionTuple]):
        current_keys = {ct.key for ct in current_tuples}
        with self._lock:
            for key in current_keys:
                if key in self._states:
                    self._states[key].touch()
                else:
                    self._states[key] = _ConnectionState()
            for key, state in self._states.items():
                if key not in current_keys and state.is_active:
                    state.mark_removed()

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


class TrafficCapture:
    def __init__(self, tracker: ProcessTracker):
        self.tracker = tracker
        self.packets: List[PacketRecord] = []
        self.remote_endpoints: Set[str] = set()
        self._stop_event = threading.Event()
        self._sniff_thread: Optional[threading.Thread] = None
        self._conn_poll_thread: Optional[threading.Thread] = None
        self._connection_tracker = ConnectionTracker(grace_seconds=GRACE_PERIOD_SECONDS)
        self._lock = threading.Lock()
        self._local_ip_cache: Set[str] = set()
        self._discarded_packets = 0
        self._accepted_packets = 0

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

    def _refresh_connections(self):
        try:
            tuples = self.tracker.get_active_connection_tuples(include_dying=False)
            self._connection_tracker.sync_from(tuples)
            self._connection_tracker.purge_expired()
        except Exception:
            pass

    def _conn_poll_worker(self):
        while not self._stop_event.is_set():
            self._refresh_connections()
            self._stop_event.wait(CONNECTION_POLL_INTERVAL)

    def _match_process_packet(self, pkt) -> Optional[PacketRecord]:
        if not (IP in pkt or IPv6 in pkt):
            return None

        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        protocol = None
        src_port = None
        dst_port = None
        payload = b""

        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        else:
            return None

        local_ips = self._local_ip_cache or self._get_local_ips()

        direction = None
        if src_ip in local_ips:
            direction = "outbound"
            ct = ConnectionTuple(
                protocol=protocol,
                local_ip=src_ip, local_port=src_port,
                remote_ip=dst_ip, remote_port=dst_port
            )
        elif dst_ip in local_ips:
            direction = "inbound"
            ct = ConnectionTuple(
                protocol=protocol,
                local_ip=dst_ip, local_port=dst_port,
                remote_ip=src_ip, remote_port=src_port
            )
        else:
            return None

        if not self._connection_tracker.contains(ct.key):
            self._discarded_packets += 1
            return None

        self._connection_tracker.touch(ct.key)
        self._accepted_packets += 1

        return PacketRecord(
            timestamp=datetime.now(),
            src_ip=src_ip, src_port=src_port,
            dst_ip=dst_ip, dst_port=dst_port,
            protocol=protocol,
            payload=payload,
            direction=direction,
            connection_key=ct.key
        )

    def _packet_callback(self, pkt):
        record = self._match_process_packet(pkt)
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
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy 未安装，无法进行流量捕获。请运行: pip install scapy")

        self._get_local_ips()
        self._refresh_connections()

        if self._connection_tracker.active_count() == 0:
            print("[!] 警告：目标进程当前没有活跃网络连接，将持续监听新连接...")
        else:
            print(f"[*] 已锁定 {self._connection_tracker.active_count()} 个活跃连接（五元组精确追踪）")

        self._stop_event.clear()

        self._conn_poll_thread = threading.Thread(target=self._conn_poll_worker, daemon=True)
        self._conn_poll_thread.start()

        bpf_filter = self._build_bpf_filter()

        def sniff_target():
            try:
                sniff(
                    filter=bpf_filter if bpf_filter else None,
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda x: self._stop_event.is_set()
                )
            except Exception as e:
                print(f"[!] 抓包错误: {e}")
                print("[!] 提示：Windows 下需要安装 Npcap (https://npcap.com/)，且需以管理员权限运行")

        self._sniff_thread = threading.Thread(target=sniff_target, daemon=True)
        self._sniff_thread.start()

        if duration:
            print(f"[*] 开始捕获流量，持续 {duration} 秒...")
            self._stop_event.wait(duration)
            self.stop()
        else:
            print("[*] 开始捕获流量，按 Ctrl+C 停止...")

    def _build_bpf_filter(self) -> str:
        ports = list(self._connection_tracker.get_active_ports())
        if not ports:
            return ""
        port_filters = []
        for p in ports:
            port_filters.append(f"port {p}")
        return " or ".join(port_filters)

    def stop(self):
        self._stop_event.set()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=5)
        if self._conn_poll_thread:
            self._conn_poll_thread.join(timeout=3)
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
