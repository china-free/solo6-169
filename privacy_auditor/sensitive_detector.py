import re
import os
import uuid
import socket
import getpass
import platform
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .payload_parser import ParsedPayload, PayloadType, PacketRecord


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SensitiveData:
    category: str
    description: str
    matches: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'category': self.category,
            'description': self.description,
            'matches': list(set(self.matches)),
            'risk_level': self.risk_level.value,
            'evidence': self.evidence
        }


class SensitiveDataDetector:
    MAC_REGEX = re.compile(
        r'\b([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\b'
    )

    IPV4_REGEX = re.compile(
        r'\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b'
    )

    IPV6_REGEX = re.compile(
        r'\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))\b'
    )

    EMAIL_REGEX = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )

    PHONE_REGEX = re.compile(
        r'\b(?:(?:\+?86)?1[3-9]\d{9}|(?:\+?1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b'
    )

    UUID_REGEX = re.compile(
        r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    )

    WINDOWS_PATH_REGEX = re.compile(
        r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.[A-Za-z0-9]{2,10}'
        r'|(?:~\\|%[A-Za-z_]+%\\)(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.[A-Za-z0-9]{2,10}'
    )

    UNIX_PATH_REGEX = re.compile(
        r'(?:/|~/)(?:[\w.\-]+/)*[\w.\-]+\.[A-Za-z0-9]{2,10}'
    )

    USERNAME_REGEX_TEMPLATE = None

    ID_CARD_REGEX = re.compile(
        r'\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b'
    )

    TELEMETRY_KEYWORDS = {
        'mac_address', 'macaddr', 'ethernet', 'hwaddr', 'physical_address',
        'machine_id', 'machineid', 'device_id', 'deviceid', 'hardware_id', 'hwid',
        'install_id', 'installid', 'installation_id',
        'uuid', 'guid', 'unique_id', 'session_id', 'trace_id',
        'computer_name', 'hostname', 'machinename', 'pc_name',
        'username', 'user_name', 'user_id', 'userid', 'login',
        'recent_files', 'recentdocs', 'mru', 'last_opened', 'recent_items',
        'home_dir', 'homedir', 'user_profile', 'userprofile', 'appdata',
        'recent_documents', 'file_history', 'file_history', 'opens',
        'uptime', 'os_version', 'osversion', 'system_version', 'kernel_version',
        'memory', 'cpu_usage', 'disk_usage', 'battery',
        'location', 'latitude', 'longitude', 'gps', 'geolocation',
        'clipboard', 'clipboard_content',
        'keylog', 'keystroke', 'input_text',
        'browser_history', 'urls_visited', 'downloads'
    }

    def __init__(self):
        self._baseline = self._collect_baseline()
        self._compile_username_regex()

    def _collect_baseline(self) -> Dict[str, Any]:
        baseline = {}
        try:
            baseline['username'] = getpass.getuser()
        except Exception:
            baseline['username'] = os.environ.get('USERNAME') or os.environ.get('USER') or ''

        try:
            baseline['hostname'] = socket.gethostname()
        except Exception:
            baseline['hostname'] = platform.node() or ''

        try:
            baseline['platform'] = platform.platform()
            baseline['os_version'] = platform.version()
            baseline['machine'] = platform.machine()
        except Exception:
            baseline['platform'] = ''
            baseline['os_version'] = ''
            baseline['machine'] = ''

        try:
            import psutil
            macs = set()
            for nic, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK and addr.address:
                        macs.add(addr.address.lower())
            baseline['mac_addresses'] = macs
        except Exception:
            baseline['mac_addresses'] = set()

        try:
            ips = set()
            for info in socket.getaddrinfo(baseline['hostname'], None):
                ips.add(info[4][0])
            baseline['local_ips'] = ips
        except Exception:
            baseline['local_ips'] = set()

        try:
            home = os.path.expanduser('~')
            baseline['home_dir'] = home
            recent_paths = []
            recent_dirs = [
                os.path.join(home, 'Recent'),
                os.path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent'),
                os.path.join(home, '.local', 'share', 'RecentDocuments'),
                os.path.join(home, 'Documents'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, 'Downloads')
            ]
            for rdir in recent_dirs:
                if os.path.isdir(rdir):
                    try:
                        for f in os.listdir(rdir)[:50]:
                            recent_paths.append(os.path.join(rdir, f))
                    except Exception:
                        pass
            baseline['recent_paths'] = recent_paths[:100]
        except Exception:
            baseline['home_dir'] = ''
            baseline['recent_paths'] = []

        return baseline

    def _compile_username_regex(self):
        username = self._baseline.get('username', '')
        if username and len(username) >= 2:
            escaped = re.escape(username)
            self.USERNAME_REGEX_TEMPLATE = re.compile(rf'\b{escaped}\b', re.IGNORECASE)

    def _check_telemetry_keywords_in_keys(self, data: Dict[str, Any]) -> List[str]:
        found = []
        if not isinstance(data, dict):
            return found
        for key in data.keys():
            key_lower = str(key).lower().replace('-', '_').replace(' ', '_')
            for kw in self.TELEMETRY_KEYWORDS:
                if kw in key_lower:
                    found.append(f"{key}={data[key]}")
                    break
        return found

    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        items = {}
        if not isinstance(d, dict):
            return items
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(self._flatten_dict(v, new_key, sep=sep))
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.update(self._flatten_dict(item, f"{new_key}[{i}]", sep=sep))
                    else:
                        items[f"{new_key}[{i}]"] = str(item)
            else:
                items[new_key] = str(v) if v is not None else ''
        return items

    def detect_from_text(self, text: str) -> List[SensitiveData]:
        findings: List[SensitiveData] = []

        if not text or len(text.strip()) == 0:
            return findings

        macs = self.MAC_REGEX.findall(text)
        if macs:
            baseline_macs = self._baseline.get('mac_addresses', set())
            matched_local = [m for m in macs if m.lower() in baseline_macs]
            if matched_local:
                findings.append(SensitiveData(
                    category="MAC_ADDRESS",
                    description="检测到本机真实 MAC 地址被发送",
                    matches=matched_local,
                    risk_level=RiskLevel.CRITICAL,
                    evidence=f"本机 MAC: {', '.join(matched_local)}"
                ))
            else:
                findings.append(SensitiveData(
                    category="MAC_ADDRESS",
                    description="检测到 MAC 地址数据",
                    matches=macs,
                    risk_level=RiskLevel.HIGH,
                    evidence=f"MAC 地址: {', '.join(macs)}"
                ))

        if self.USERNAME_REGEX_TEMPLATE:
            uname_matches = self.USERNAME_REGEX_TEMPLATE.findall(text)
            if uname_matches:
                findings.append(SensitiveData(
                    category="USERNAME",
                    description=f"检测到系统用户名 '{self._baseline['username']}'",
                    matches=list(set(uname_matches)),
                    risk_level=RiskLevel.HIGH,
                    evidence=f"用户名: {self._baseline['username']}"
                ))

        hostname = self._baseline.get('hostname', '')
        if hostname and len(hostname) >= 3:
            escaped_host = re.escape(hostname)
            if re.search(rf'\b{escaped_host}\b', text, re.IGNORECASE):
                findings.append(SensitiveData(
                    category="HOSTNAME",
                    description=f"检测到计算机名 '{hostname}'",
                    matches=[hostname],
                    risk_level=RiskLevel.MEDIUM,
                    evidence=f"计算机名: {hostname}"
                ))

        recent_paths = self._baseline.get('recent_paths', [])
        leaked_paths = []
        for p in recent_paths[:50]:
            basename = os.path.basename(p)
            if len(basename) >= 5 and basename in text:
                leaked_paths.append(p)
        win_paths = self.WINDOWS_PATH_REGEX.findall(text)
        unix_paths = self.UNIX_PATH_REGEX.findall(text)
        all_paths = list(set(leaked_paths + win_paths + unix_paths))
        if all_paths:
            findings.append(SensitiveData(
                category="FILE_PATH",
                description="检测到本地文件路径或最近打开的文件信息",
                matches=all_paths[:20],
                risk_level=RiskLevel.HIGH,
                evidence=f"文件路径/最近文件: {', '.join(all_paths[:10])}"
            ))

        emails = self.EMAIL_REGEX.findall(text)
        if emails:
            findings.append(SensitiveData(
                category="EMAIL",
                description="检测到邮箱地址",
                matches=list(set(emails)),
                risk_level=RiskLevel.HIGH,
                evidence=f"邮箱: {', '.join(set(emails))}"
            ))

        phones = self.PHONE_REGEX.findall(text)
        if phones:
            findings.append(SensitiveData(
                category="PHONE",
                description="检测到电话号码",
                matches=list(set(phones)),
                risk_level=RiskLevel.CRITICAL,
                evidence=f"电话: {', '.join(set(phones))}"
            ))

        uuids = self.UUID_REGEX.findall(text)
        if uuids:
            findings.append(SensitiveData(
                category="UUID",
                description="检测到 UUID/GUID 设备标识符",
                matches=list(set(uuids)),
                risk_level=RiskLevel.MEDIUM,
                evidence=f"UUID: {', '.join(set(uuids))}"
            ))

        ids = self.ID_CARD_REGEX.findall(text)
        if ids:
            findings.append(SensitiveData(
                category="ID_CARD",
                description="检测到身份证号!",
                matches=list(set(ids)),
                risk_level=RiskLevel.CRITICAL,
                evidence=f"身份证号: {', '.join(set(ids))}"
            ))

        home_dir = self._baseline.get('home_dir', '')
        if home_dir and home_dir in text:
            findings.append(SensitiveData(
                category="HOME_DIR",
                description=f"检测到用户主目录路径",
                matches=[home_dir],
                risk_level=RiskLevel.MEDIUM,
                evidence=f"主目录: {home_dir}"
            ))

        return findings

    def detect_from_payload(self, parsed: ParsedPayload) -> List[SensitiveData]:
        all_findings: List[SensitiveData] = []

        all_findings.extend(self.detect_from_text(parsed.raw_text))

        kvs = parsed.extract_all_key_values()
        flat_kvs = self._flatten_dict(kvs)

        telemetry_hits = self._check_telemetry_keywords_in_keys(flat_kvs)
        if telemetry_hits:
            all_findings.append(SensitiveData(
                category="TELEMETRY_FIELDS",
                description="检测到典型遥测字段（包含设备标识、使用数据等）",
                matches=telemetry_hits[:30],
                risk_level=RiskLevel.HIGH,
                evidence=f"遥测字段: {'; '.join(telemetry_hits[:10])}"
            ))

        return all_findings

    def detect_many(self, parsed_list: List[Tuple[PacketRecord, ParsedPayload]]) -> Dict[str, Any]:
        total_findings: List[SensitiveData] = []
        by_category: Dict[str, List[SensitiveData]] = {}

        for packet, parsed in parsed_list:
            findings = self.detect_from_payload(parsed)
            for f in findings:
                total_findings.append(f)
                by_category.setdefault(f.category, []).append(f)

        summary = self._merge_findings(total_findings)

        return {
            'total_findings_count': len(total_findings),
            'categories_found': list(by_category.keys()),
            'summary': summary,
            'baseline': {
                'username': self._baseline.get('username', ''),
                'hostname': self._baseline.get('hostname', ''),
                'mac_count': len(self._baseline.get('mac_addresses', set())),
                'recent_files_checked': len(self._baseline.get('recent_paths', []))
            }
        }

    @staticmethod
    def _merge_findings(findings: List[SensitiveData]) -> List[SensitiveData]:
        merged: Dict[str, SensitiveData] = {}
        for f in findings:
            key = f.category
            if key in merged:
                existing = merged[key]
                existing.matches.extend(f.matches)
                existing.matches = list(set(existing.matches))
                if f.risk_level.value in ('critical', 'high') and existing.risk_level.value not in ('critical', 'high'):
                    existing.risk_level = f.risk_level
            else:
                merged[key] = SensitiveData(
                    category=f.category,
                    description=f.description,
                    matches=list(set(f.matches)),
                    risk_level=f.risk_level,
                    evidence=f.evidence
                )
        return list(merged.values())
