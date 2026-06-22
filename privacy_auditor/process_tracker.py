import psutil
from typing import Optional, List, Dict, Any
import socket
import ipaddress


class ProcessTracker:
    def __init__(self, pid: Optional[int] = None, process_name: Optional[str] = None):
        self.pid = pid
        self.process_name = process_name
        self._process: Optional[psutil.Process] = None

    def find_process(self) -> psutil.Process:
        if self.pid:
            try:
                self._process = psutil.Process(self.pid)
                return self._process
            except psutil.NoSuchProcess:
                raise ValueError(f"未找到 PID 为 {self.pid} 的进程")

        if self.process_name:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if self.process_name.lower() in proc.info['name'].lower():
                        self._process = psutil.Process(proc.info['pid'])
                        self.pid = proc.info['pid']
                        return self._process
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            raise ValueError(f"未找到名称包含 '{self.process_name}' 的进程")

        raise ValueError("必须指定 pid 或 process_name")

    def get_process_info(self) -> Dict[str, Any]:
        if not self._process:
            self.find_process()
        try:
            with self._process.oneshot():
                info = {
                    'pid': self._process.pid,
                    'name': self._process.name(),
                    'status': self._process.status(),
                    'username': self._process.username(),
                    'create_time': self._process.create_time(),
                    'exe': self._process.exe(),
                    'cmdline': self._process.cmdline(),
                    'connections': self.get_connections()
                }
                return info
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            raise RuntimeError(f"无法获取进程信息: {e}")

    def get_connections(self) -> List[Dict[str, Any]]:
        if not self._process:
            self.find_process()
        connections = []
        try:
            for conn in self._process.net_connections(kind='inet'):
                conn_info = {
                    'fd': conn.fd,
                    'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                    'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'remote_ip': conn.raddr.ip if conn.raddr else None,
                    'remote_port': conn.raddr.port if conn.raddr else None,
                    'status': conn.status
                }
                connections.append(conn_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return connections

    def get_local_ports(self) -> List[int]:
        if not self._process:
            self.find_process()
        ports = []
        try:
            for conn in self._process.net_connections(kind='inet'):
                if conn.laddr:
                    ports.append(conn.laddr.port)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return list(set(ports))

    @staticmethod
    def is_external_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
        except ValueError:
            return False

    def poll_connections(self) -> List[Dict[str, Any]]:
        return self.get_connections()
