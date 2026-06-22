import threading
import time
import socket
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .process_tracker import ProcessTracker


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
        direction: str = "outbound"
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.payload = payload
        self.direction = direction

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


class TrafficCapture:
    def __init__(self, tracker: ProcessTracker):
        self.tracker = tracker
        self.packets: List[PacketRecord] = []
        self.remote_endpoints: Set[str] = set()
        self._stop_event = threading.Event()
        self._sniff_thread: Optional[threading.Thread] = None
        self._port_poll_thread: Optional[threading.Thread] = None
        self._known_local_ports: Set[int] = set()
        self._lock = threading.Lock()
        self._local_ip_cache: Set[str] = set()

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

    def _refresh_ports(self):
        try:
            ports = set(self.tracker.get_local_ports())
            with self._lock:
                self._known_local_ports.update(ports)
        except Exception:
            pass

    def _port_poll_worker(self, interval: float = 2.0):
        while not self._stop_event.is_set():
            self._refresh_ports()
            self._stop_event.wait(interval)

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

        direction = None
        matched_port = None

        with self._lock:
            known_ports = self._known_local_ports.copy()

        local_ips = self._local_ip_cache or self._get_local_ips()

        if src_ip in local_ips and src_port in known_ports:
            direction = "outbound"
            matched_port = src_port
        elif dst_ip in local_ips and dst_port in known_ports:
            direction = "inbound"
            matched_port = dst_port
        elif src_port in known_ports:
            direction = "outbound"
            matched_port = src_port
        elif dst_port in known_ports:
            direction = "inbound"
            matched_port = dst_port

        if not direction:
            return None

        return PacketRecord(
            timestamp=datetime.now(),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            payload=payload,
            direction=direction
        )

    def _packet_callback(self, pkt):
        record = self._match_process_packet(pkt)
        if record:
            with self._lock:
                self.packets.append(record)
                if record.direction == "outbound" and ProcessTracker.is_external_ip(record.dst_ip):
                    self.remote_endpoints.add(f"{record.dst_ip}:{record.dst_port}")

    def start(self, duration: Optional[int] = None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy 未安装，无法进行流量捕获。请运行: pip install scapy")

        self._get_local_ips()
        self._refresh_ports()

        if not self._known_local_ports:
            print("[!] 警告：目标进程当前没有网络连接，将持续监听新连接...")

        self._stop_event.clear()

        self._port_poll_thread = threading.Thread(target=self._port_poll_worker, daemon=True)
        self._port_poll_thread.start()

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
        with self._lock:
            ports = list(self._known_local_ports)
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
        if self._port_poll_thread:
            self._port_poll_thread.join(timeout=3)

    def get_outbound_packets(self) -> List[PacketRecord]:
        with self._lock:
            return [p for p in self.packets if p.direction == "outbound"]

    def get_external_endpoints(self) -> Set[str]:
        return self.remote_endpoints.copy()

    def get_packets_with_payload(self) -> List[PacketRecord]:
        with self._lock:
            return [p for p in self.packets if p.payload and len(p.payload) > 0]


import psutil
