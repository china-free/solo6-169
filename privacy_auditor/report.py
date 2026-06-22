import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from colorama import init, Fore, Style, Back

from .traffic_capture import TrafficCapture, PacketRecord
from .payload_parser import PayloadParser, ParsedPayload, PayloadType
from .sensitive_detector import SensitiveDataDetector, SensitiveData, RiskLevel
from .process_tracker import ProcessTracker


init(autoreset=True)


class PrivacyReport:
    RISK_COLORS = {
        RiskLevel.LOW: Fore.CYAN,
        RiskLevel.MEDIUM: Fore.YELLOW,
        RiskLevel.HIGH: Fore.MAGENTA,
        RiskLevel.CRITICAL: Fore.RED
    }

    RISK_BADGE = {
        RiskLevel.LOW: "[低]",
        RiskLevel.MEDIUM: "[中]",
        RiskLevel.HIGH: "[高]",
        RiskLevel.CRITICAL: "[严重]"
    }

    TYPE_LABELS = {
        PayloadType.HTTP_REQUEST: "HTTP请求",
        PayloadType.HTTP_RESPONSE: "HTTP响应",
        PayloadType.JSON: "JSON数据",
        PayloadType.FORM_URLENCODED: "表单数据",
        PayloadType.TELEMETRY: "遥测数据 ⚠",
        PayloadType.PLAINTEXT: "明文",
        PayloadType.BINARY: "二进制",
        PayloadType.UNKNOWN: "未知"
    }

    def __init__(
        self,
        tracker: ProcessTracker,
        capture: TrafficCapture,
        detector: SensitiveDataDetector,
        duration: int = 0
    ):
        self.tracker = tracker
        self.capture = capture
        self.detector = detector
        self.duration = duration
        self.start_time = datetime.now()

    def _hr(self, char: str = '=', width: int = 72):
        print(Fore.CYAN + char * width)

    def _section_title(self, title: str):
        self._hr()
        print(Fore.CYAN + f"  {title}")
        self._hr('-')

    def _banner(self):
        self._hr('=')
        print(Fore.CYAN + Style.BRIGHT + "  ╔══════════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + Style.BRIGHT + "  ║            单进程级网络遥测 隐私审计器  v0.1.0              ║")
        print(Fore.CYAN + Style.BRIGHT + "  ╚══════════════════════════════════════════════════════════════╝")
        print()

    def print_process_info(self):
        self._section_title("审计目标进程")
        try:
            info = self.tracker.get_process_info()
            print(f"  PID:         {Fore.GREEN}{info['pid']}")
            print(f"  进程名:      {Fore.GREEN}{info['name']}")
            print(f"  可执行文件:  {Fore.WHITE}{info.get('exe', 'N/A')}")
            print(f"  启动用户:    {Fore.WHITE}{info.get('username', 'N/A')}")
            print(f"  当前状态:    {Fore.WHITE}{info.get('status', 'N/A')}")

            cmdline = info.get('cmdline', [])
            if cmdline:
                print(f"  启动命令:    {Fore.WHITE}{' '.join(cmdline)[:150]}")

            conns = info.get('connections', [])
            external = [c for c in conns if c.get('remote_ip') and ProcessTracker.is_external_ip(c['remote_ip'])]
            print(f"  网络连接:    {Fore.YELLOW}总计 {len(conns)} 个，外部 {len(external)} 个")
            for c in external[:8]:
                print(f"    → {Fore.RED}{c['type']} {c['remote_address']}  [{c.get('status', '')}]")
        except Exception as e:
            print(f"  {Fore.RED}获取进程信息失败: {e}")
        print()

    def print_endpoints(self, endpoints):
        self._section_title("外部通信节点 (仅出站)")
        if not endpoints:
            print(f"  {Fore.GREEN}未检测到外部出站流量 ✓")
        else:
            print(f"  共发现 {Fore.RED}{len(endpoints)}{Fore.WHITE} 个外部端点：")
            sorted_eps = sorted(endpoints)
            for ep in sorted_eps:
                print(f"    {Fore.RED}● {ep}")
        print()

    def print_traffic_stats(self, packets: List[PacketRecord]):
        self._section_title("捕获流量统计")
        outbound = [p for p in packets if p.direction == 'outbound']
        inbound = [p for p in packets if p.direction == 'inbound']
        with_payload = [p for p in packets if p.payload and len(p.payload) > 0]

        print(f"  总包数:       {Fore.CYAN}{len(packets)}")
        print(f"  出站包数:     {Fore.RED}{len(outbound)}")
        print(f"  入站包数:     {Fore.BLUE}{len(inbound)}")
        print(f"  含 payload:   {Fore.YELLOW}{len(with_payload)}")

        total_bytes = sum(len(p.payload) for p in packets if p.payload)
        print(f"  payload 总量: {Fore.CYAN}{total_bytes} bytes")
        if self.duration > 0:
            print(f"  捕获时长:     {Fore.WHITE}{self.duration}s")
        print()

    def print_parsed_payloads(self, parsed_list: List[Tuple[PacketRecord, ParsedPayload]]):
        self._section_title("解析到的明文出站流量 (前 20 条)")
        outbound_parsed = [
            (pkt, pp) for pkt, pp in parsed_list
            if pkt.direction == 'outbound'
        ]
        if not outbound_parsed:
            print(f"  {Fore.GREEN}未捕获到可解析的明文出站流量 ✓")
        else:
            show_count = min(20, len(outbound_parsed))
            print(f"  共解析 {Fore.YELLOW}{len(outbound_parsed)}{Fore.WHITE} 条，显示 {show_count} 条：")
            print()
            for i, (pkt, pp) in enumerate(outbound_parsed[:show_count], 1):
                type_label = self.TYPE_LABELS.get(pp.payload_type, str(pp.payload_type))
                type_color = Fore.MAGENTA if pp.payload_type == PayloadType.TELEMETRY else Fore.YELLOW
                print(f"  {Fore.WHITE}[{i:2d}] {type_color}{type_label}")
                print(f"       {Fore.WHITE}{pkt.src_ip}:{pkt.src_port} → {Fore.RED}{pkt.dst_ip}:{pkt.dst_port}  ({pkt.protocol})")

                if pp.http_request:
                    hr = pp.http_request
                    print(f"       {Fore.GREEN}{hr.method} {Fore.WHITE}{hr.path[:100]}")
                    if hr.host:
                        print(f"       {Fore.WHITE}Host: {hr.host}")
                    if hr.user_agent:
                        print(f"       {Fore.WHITE}UA: {hr.user_agent[:80]}")
                    if hr.body_parsed:
                        print(f"       {Fore.WHITE}Body: {self._truncate_dict(hr.body_parsed)}")
                    elif hr.body.strip():
                        print(f"       {Fore.WHITE}BodyRaw: {hr.body.strip()[:120]}")
                elif pp.json_data:
                    print(f"       {Fore.WHITE}JSON: {self._truncate_dict(pp.json_data)}")
                elif pp.form_data:
                    print(f"       {Fore.WHITE}Form: {self._truncate_dict(pp.form_data)}")
                elif pp.plaintext:
                    print(f"       {Fore.WHITE}Text: {pp.plaintext[:150]}")
                print()

    def _truncate_dict(self, d: Dict[str, Any], max_len: int = 200) -> str:
        try:
            import json
            s = json.dumps(d, ensure_ascii=False)
            if len(s) > max_len:
                s = s[:max_len] + " ...}"
            return s
        except Exception:
            return str(d)[:max_len]

    def print_privacy_findings(self, detection_result: Dict[str, Any]):
        self._section_title("⚠  隐 私 泄 露 审 计 结 果  ⚠")
        summary: List[SensitiveData] = detection_result.get('summary', [])

        if not summary:
            print(f"  {Fore.GREEN}{Style.BRIGHT}✓ 未检测到明显的敏感数据泄露。")
            print()
            return

        critical_count = sum(1 for f in summary if f.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for f in summary if f.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for f in summary if f.risk_level == RiskLevel.MEDIUM)

        print(Style.BRIGHT, end='')
        print(f"  {Fore.RED}严重: {critical_count}   {Fore.MAGENTA}高: {high_count}   {Fore.YELLOW}中: {medium_count}")
        print()
        print(Style.BRIGHT + "  该进程可能正在悄悄上传以下隐私数据：")
        print()

        sorted_summary = sorted(
            summary,
            key=lambda f: {
                RiskLevel.CRITICAL: 0,
                RiskLevel.HIGH: 1,
                RiskLevel.MEDIUM: 2,
                RiskLevel.LOW: 3
            }.get(f.risk_level, 99)
        )

        for finding in sorted_summary:
            color = self.RISK_COLORS.get(finding.risk_level, Fore.WHITE)
            badge = self.RISK_BADGE.get(finding.risk_level, "")

            print(f"  {color}{Style.BRIGHT}{badge} {finding.description}{Style.RESET_ALL}")
            if finding.matches:
                unique_matches = list(set(finding.matches))
                display = unique_matches[:8]
                print(f"       {Fore.WHITE}发现 {len(unique_matches)} 处: {', '.join(str(m) for m in display)}")
                if len(unique_matches) > 8:
                    print(f"       {Fore.WHITE}... 另有 {len(unique_matches) - 8} 处省略")
            print()

    def print_baseline_info(self, detection_result: Dict[str, Any]):
        self._section_title("本机敏感特征库 (用于匹配)")
        baseline = detection_result.get('baseline', {})
        print(f"  当前用户:    {Fore.YELLOW}{baseline.get('username', 'N/A')}")
        print(f"  计算机名:    {Fore.YELLOW}{baseline.get('hostname', 'N/A')}")
        print(f"  网卡 MAC:    {Fore.YELLOW}{baseline.get('mac_count', 0)} 个已索引")
        print(f"  最近文件:    {Fore.YELLOW}{baseline.get('recent_files_checked', 0)} 个已索引")
        print()

    def print_summary(self, detection_result: Dict[str, Any]):
        self._hr('=')
        print()
        summary_findings = detection_result.get('summary', [])

        if not summary_findings:
            print(f"  {Fore.GREEN}{Style.BRIGHT}审计结论: 该进程未检测到明显的隐私数据外泄。")
        else:
            worst = max(
                summary_findings,
                key=lambda f: {
                    RiskLevel.CRITICAL: 4,
                    RiskLevel.HIGH: 3,
                    RiskLevel.MEDIUM: 2,
                    RiskLevel.LOW: 1
                }.get(f.risk_level, 0)
            )
            if worst.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                print(f"  {Fore.RED}{Style.BRIGHT}⚠ 审计结论: 检测到高度可疑的隐私数据外泄，请立即审查！")
                print(f"  {Fore.RED}  最严重问题: {worst.description}")
            else:
                print(f"  {Fore.YELLOW}⚠ 审计结论: 检测到潜在隐私数据外泄，建议关注。")

        print()
        print(f"  报告生成时间: {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._hr('=')
        print()

    def print_full(self):
        self._banner()

        self.print_process_info()

        endpoints = self.capture.get_external_endpoints()
        self.print_endpoints(endpoints)

        all_packets = self.capture.packets
        self.print_traffic_stats(all_packets)

        packets_with_payload = self.capture.get_packets_with_payload()
        parsed_list = PayloadParser.parse_many(packets_with_payload)

        self.print_parsed_payloads(parsed_list)

        detection_result = self.detector.detect_many(parsed_list)

        self.print_privacy_findings(detection_result)

        self.print_baseline_info(detection_result)

        self.print_summary(detection_result)
