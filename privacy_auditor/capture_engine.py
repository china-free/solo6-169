import abc
import subprocess
import threading
import time
import struct
import socket
from typing import List, Dict, Any, Optional, Callable, Set, Tuple
from datetime import datetime
from dataclasses import dataclass
import shutil
import sys
import os

from .process_tracker import ConnectionTuple


@dataclass
class RawPacketMeta:
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    payload: bytes
    packet_len: int


PacketCallback = Callable[[RawPacketMeta], None]


class CaptureEngine(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def is_available(self) -> bool:
        ...

    @abc.abstractmethod
    def start(
        self,
        bpf_filter: str,
        callback: PacketCallback,
        stop_event: threading.Event,
        interface: Optional[str] = None
    ):
        ...

    @abc.abstractmethod
    def stop(self):
        ...

    def build_bpf_filter(
        self,
        connections: Set[ConnectionTuple],
        extra_ports: Optional[Set[int]] = None
    ) -> str:
        if not connections and not extra_ports:
            return ""
        clauses: List[str] = []
        for ct in connections:
            ip_ver = "ip6" if ":" in ct.local_ip else "ip"
            proto = ct.protocol.lower()
            clauses.append(
                f"({ip_ver} and {proto} and "
                f"((host {ct.local_ip} and {proto} port {ct.local_port} and "
                f"host {ct.remote_ip} and {proto} port {ct.remote_port}))"
            )
        if extra_ports:
            for p in extra_ports:
                clauses.append(f"(tcp port {p} or udp port {p})")
        return " or ".join(clauses)


class SubprocessDumpcapEngine(CaptureEngine):
    name = "dumpcap"
    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_NSEC_MAGIC = 0xa1b23c4d

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None
        self._callback: Optional[PacketCallback] = None
        self._linktype = 1

    def is_available(self) -> bool:
        return shutil.which("dumpcap") is not None or shutil.which("tshark") is not None

    def _get_cmd(self, bpf_filter: str, interface: Optional[str]) -> List[str]:
        for tool in ["dumpcap", "tshark", "tcpdump"]:
            if shutil.which(tool):
                if tool == "tcpdump":
                    cmd = [tool, "-U", "-w", "-", "-s", "65535"]
                    if interface:
                        cmd += ["-i", interface]
                    if bpf_filter:
                        cmd.append(bpf_filter)
                    return cmd
                elif tool == "tshark":
                    cmd = [tool, "-w", "-", "-F", "pcap", "-s", "65535"]
                    if interface:
                        cmd += ["-i", interface]
                    if bpf_filter:
                        cmd += ["-f", bpf_filter]
                    return cmd
                else:
                    cmd = [tool, "-P", "-w", "-", "-s", "65535"]
                    if interface:
                        cmd += ["-i", interface]
                    if bpf_filter:
                        cmd += ["-f", bpf_filter]
                    return cmd
        raise RuntimeError("No capture tool available")

    @staticmethod
    def _parse_ipv4(data: bytes, offset: int) -> Tuple[int, str, str, int, int, bytes]:
        ver_ihl = data[offset]
        ihl = (ver_ihl & 0x0f) * 4
        total_len = struct.unpack('>H', data[offset+2:offset+4])[0]
        protocol = data[offset+9]
        src = socket.inet_ntoa(data[offset+12:offset+16])
        dst = socket.inet_ntoa(data[offset+16:offset+20])
        ip_payload = data[offset+ihl:offset+total_len]
        return protocol, src, dst, ihl, total_len, ip_payload

    @staticmethod
    def _parse_ipv6(data: bytes, offset: int) -> Tuple[int, str, str, int, int, bytes]:
        payload_len = struct.unpack('>H', data[offset+4:offset+6])[0]
        next_header = data[offset+6]
        src = socket.inet_ntop(socket.AF_INET6, data[offset+8:offset+24])
        dst = socket.inet_ntop(socket.AF_INET6, data[offset+24:offset+40])
        ip_payload = data[offset+40:offset+40+payload_len]
        return next_header, src, dst, 40, 40+payload_len, ip_payload

    @classmethod
    def _parse_ethernet(cls, data: bytes) -> Optional[Tuple[int, str, str, str, bytes]]:
        if len(data) < 14:
            return None
        eth_type = struct.unpack('>H', data[12:14])[0]
        offset = 14
        if eth_type == 0x8100:
            if len(data) < 18:
                return None
            eth_type = struct.unpack('>H', data[16:18])[0]
            offset = 18
        protocol = 0
        src_ip = ""
        dst_ip = ""
        proto_str = ""
        transport_payload = b""
        if eth_type == 0x0800:
            protocol, src_ip, dst_ip, _, _, ip_payload = cls._parse_ipv4(data, offset)
            if protocol == 6:
                proto_str = "TCP"
                if len(ip_payload) >= 20:
                    src_port, dst_port = struct.unpack('>HH', ip_payload[0:4])
                    data_offset = (ip_payload[12] >> 4) * 4
                    transport_payload = ip_payload[data_offset:]
                    return proto_str, src_ip, src_port, dst_ip, dst_port, transport_payload
            elif protocol == 17:
                proto_str = "UDP"
                if len(ip_payload) >= 8:
                    src_port, dst_port = struct.unpack('>HH', ip_payload[0:4])
                    transport_payload = ip_payload[8:]
                    return proto_str, src_ip, src_port, dst_ip, dst_port, transport_payload
            return None
        elif eth_type == 0x86dd:
            protocol, src_ip, dst_ip, _, _, ip_payload = cls._parse_ipv6(data, offset)
            if protocol == 6:
                proto_str = "TCP"
                if len(ip_payload) >= 20:
                    src_port, dst_port = struct.unpack('>HH', ip_payload[0:4])
                    data_offset = (ip_payload[12] >> 4) * 4
                    transport_payload = ip_payload[data_offset:]
                    return proto_str, src_ip, src_port, dst_ip, dst_port, transport_payload
            elif protocol == 17:
                proto_str = "UDP"
                if len(ip_payload) >= 8:
                    src_port, dst_port = struct.unpack('>HH', ip_payload[0:4])
                    transport_payload = ip_payload[8:]
                    return proto_str, src_ip, src_port, dst_ip, dst_port, transport_payload
            return None
        return None

    def _pcap_reader(self):
        assert self._proc and self._proc.stdout and self._stop_event
        try:
            header = self._proc.stdout.read(24)
            if len(header) < 24:
                return
            magic = struct.unpack('<I', header[0:4])[0]
            if magic == self.PCAP_NSEC_MAGIC:
                ts_scale = 1e-9
            else:
                ts_scale = 1e-6
            self._linktype = struct.unpack('<I', header[20:24])[0]

            while not self._stop_event.is_set() and self._proc.poll() is None:
                pkt_header = self._proc.stdout.read(16)
                if len(pkt_header) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
                timestamp = datetime.fromtimestamp(ts_sec + ts_usec * ts_scale)
                pkt_data = self._proc.stdout.read(incl_len)
                if len(pkt_data) < incl_len:
                    break
                try:
                    if self._linktype == 1:
                        parsed = self._parse_ethernet(pkt_data)
                        if parsed and self._callback:
                            proto, src_ip, src_port, dst_ip, dst_port, payload = parsed
                            self._callback(RawPacketMeta(
                                timestamp=timestamp,
                                src_ip=src_ip,
                                src_port=src_port,
                                dst_ip=dst_ip,
                                dst_port=dst_port,
                                protocol=proto,
                                payload=payload,
                                packet_len=orig_len
                            ))
                    elif self._linktype == 12:
                        proto, src_ip, dst_ip, ihl, total_len, ip_payload = self._parse_ipv4(pkt_data, 0)
                        if proto == 6 and len(ip_payload) >= 20:
                            src_port, dst_port = struct.unpack('>HH', ip_payload[0:4])
                            data_offset = (ip_payload[12] >> 4) * 4
                            tp = ip_payload[data_offset:]
                            if self._callback:
                                self._callback(RawPacketMeta(
                                    timestamp=timestamp,
                                    src_ip=src_ip,
                                    src_port=src_port,
                                    dst_ip=dst_ip,
                                    dst_port=dst_port,
                                    protocol="TCP",
                                    payload=tp,
                                    packet_len=orig_len
                                ))
                        elif proto == 17 and len(ip_payload) >= 8:
                            src_port, dst_port = struct.unpack('>HH', ip_payload[0:4])
                            tp = ip_payload[8:]
                            if self._callback:
                                self._callback(RawPacketMeta(
                                    timestamp=timestamp,
                                    src_ip=src_ip,
                                    src_port=src_port,
                                    dst_ip=dst_ip,
                                    dst_port=dst_port,
                                    protocol="UDP",
                                    payload=tp,
                                    packet_len=orig_len
                                ))
                except Exception:
                    continue
        except Exception:
            pass

    def start(
        self,
        bpf_filter: str,
        callback: PacketCallback,
        stop_event: threading.Event,
        interface: Optional[str] = None
    ):
        self._callback = callback
        self._stop_event = stop_event
        cmd = self._get_cmd(bpf_filter, interface)
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            creationflags=creationflags
        )
        self._reader_thread = threading.Thread(target=self._pcap_reader, daemon=True)
        self._reader_thread.start()

    def stop(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                time.sleep(0.2)
                if self._proc.poll() is None:
                    self._proc.kill()
            except Exception:
                pass
        if self._reader_thread:
            self._reader_thread.join(timeout=3)


class PysharkEngine(CaptureEngine):
    name = "pyshark"

    def __init__(self):
        self._capture = None
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None
        self._callback: Optional[PacketCallback] = None

    def is_available(self) -> bool:
        try:
            import pyshark
            return True
        except ImportError:
            return False

    def _packet_to_meta(self, pkt) -> Optional[RawPacketMeta]:
        try:
            if not hasattr(pkt, 'ip') and not hasattr(pkt, 'ipv6'):
                return None
            protocol = ""
            src_ip = ""
            dst_ip = ""
            src_port = 0
            dst_port = 0
            payload = b""

            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
            elif hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst

            if hasattr(pkt, 'tcp'):
                protocol = "TCP"
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                if hasattr(pkt.tcp, 'payload') and hasattr(pkt.tcp.payload, 'binary_value'):
                    payload = pkt.tcp.payload.binary_value
            elif hasattr(pkt, 'udp'):
                protocol = "UDP"
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
                if hasattr(pkt.udp, 'payload') and hasattr(pkt.udp.payload, 'binary_value'):
                    payload = pkt.udp.payload.binary_value
            else:
                return None

            ts = float(pkt.sniff_timestamp)
            return RawPacketMeta(
                timestamp=datetime.fromtimestamp(ts),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                payload=payload,
                packet_len=int(pkt.length) if hasattr(pkt, 'length') else 0
            )
        except Exception:
            return None

    def _reader(self, capture):
        assert self._callback and self._stop_event
        try:
            for pkt in capture:
                if self._stop_event.is_set():
                    break
                meta = self._packet_to_meta(pkt)
                if meta:
                    self._callback(meta)
        except Exception:
            pass

    def start(
        self,
        bpf_filter: str,
        callback: PacketCallback,
        stop_event: threading.Event,
        interface: Optional[str] = None
    ):
        import pyshark
        self._callback = callback
        self._stop_event = stop_event
        self._capture = pyshark.LiveCapture(
            interface=interface,
            bpf_filter=bpf_filter if bpf_filter else None,
            use_json=True,
            include_raw=True
        )
        self._reader_thread = threading.Thread(
            target=self._reader,
            args=(self._capture,),
            daemon=True
        )
        self._reader_thread.start()

    def stop(self):
        if self._capture:
            try:
                self._capture.close()
            except Exception:
                pass
        if self._reader_thread:
            self._reader_thread.join(timeout=3)


class ScapyEngine(CaptureEngine):
    name = "scapy"

    def __init__(self):
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None
        self._callback: Optional[PacketCallback] = None

    def is_available(self) -> bool:
        try:
            from scapy.all import sniff
            return True
        except ImportError:
            return False

    def start(
        self,
        bpf_filter: str,
        callback: PacketCallback,
        stop_event: threading.Event,
        interface: Optional[str] = None
    ):
        from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw
        self._callback = callback
        self._stop_event = stop_event

        def _pkt_handler(pkt):
            try:
                if not (IP in pkt or IPv6 in pkt):
                    return
                ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ""
                src_port = 0
                dst_port = 0
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
                    return
                self._callback(RawPacketMeta(
                    timestamp=datetime.fromtimestamp(float(pkt.time)),
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    payload=payload,
                    packet_len=len(pkt)
                ))
            except Exception:
                pass

        def _sniffer():
            try:
                sniff(
                    iface=interface,
                    filter=bpf_filter if bpf_filter else None,
                    prn=_pkt_handler,
                    store=False,
                    stop_filter=lambda x: stop_event.is_set()
                )
            except Exception:
                pass

        self._sniff_thread = threading.Thread(target=_sniffer, daemon=True)
        self._sniff_thread.start()

    def stop(self):
        if self._sniff_thread:
            self._sniff_thread.join(timeout=3)


def get_best_engine() -> Tuple[CaptureEngine, List[str]]:
    engines = [
        (PysharkEngine(), ["pyshark", "tshark"]),
        (SubprocessDumpcapEngine(), ["dumpcap or tshark or tcpdump", "Npcap/WinPcap/libpcap"]),
        (ScapyEngine(), ["scapy", "Npcap/WinPcap/libpcap"])
    ]
    available: List[Tuple[CaptureEngine, List[str]]] = []
    for engine, reqs in engines:
        if engine.is_available():
            available.append((engine, reqs))
    if not available:
        raise RuntimeError(
            "No packet capture engine available. Install one of:\n"
            "  - pyshark + tshark (Wireshark): pip install pyshark, install Wireshark\n"
            "  - dumpcap/tshark/tcpdump + Npcap/WinPcap/libpcap\n"
            "  - scapy + Npcap: pip install scapy, install Npcap from https://npcap.com/"
        )
    return available[0]
