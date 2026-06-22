import argparse
import sys
import signal
import time

from .process_tracker import ProcessTracker
from .traffic_capture import TrafficCapture
from .sensitive_detector import SensitiveDataDetector
from .report import PrivacyReport


def _signal_handler(sig, frame, capture: TrafficCapture):
    print("\n[*] 正在停止捕获并生成报告...")
    capture.stop()


def list_processes(keyword: str = None):
    import psutil
    print(f"{'PID':>8}  {'NAME':<30} {'CONNS':>6}  {'USER':<20}")
    print("-" * 72)
    count = 0
    for proc in sorted(psutil.process_iter(['pid', 'name', 'username']), key=lambda p: p.info.get('pid', 0)):
        try:
            name = proc.info.get('name', '')
            if keyword and keyword.lower() not in name.lower():
                continue
            pid = proc.info.get('pid', 0)
            user = proc.info.get('username', '') or ''
            try:
                p = psutil.Process(pid)
                nconns = len(p.net_connections(kind='inet'))
            except Exception:
                nconns = 0
            print(f"{pid:>8}  {name[:28]:<30} {nconns:>6}  {user[:18]:<20}")
            count += 1
        except Exception:
            continue
    print(f"\n共 {count} 个进程")


def run_audit(pid: int = None, process_name: str = None, duration: int = 30):
    try:
        tracker = ProcessTracker(pid=pid, process_name=process_name)
        process = tracker.find_process()
    except ValueError as e:
        print(f"[错误] {e}")
        print("       使用 --list 查看正在运行的进程列表")
        sys.exit(1)

    print(f"[*] 已锁定目标进程: {tracker._process.name()} (PID={tracker.pid})")

    try:
        detector = SensitiveDataDetector()
    except Exception as e:
        print(f"[!] 警告: 敏感数据检测器初始化失败: {e}")
        detector = None

    capture = TrafficCapture(tracker)

    def handler(sig, frame):
        _signal_handler(sig, frame, capture)

    signal.signal(signal.SIGINT, handler)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, handler)

    try:
        capture.start(duration=duration)
        if duration:
            for remaining in range(duration, 0, -1):
                if not capture._sniff_thread or not capture._sniff_thread.is_alive():
                    break
                time.sleep(1)
                if remaining <= 5:
                    print(f"\r[*] 还剩 {remaining} 秒...", end='', flush=True)
            print()
            capture.stop()
        else:
            while capture._sniff_thread and capture._sniff_thread.is_alive():
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 用户中断，正在生成报告...")
        capture.stop()
    except Exception as e:
        print(f"\n[错误] 捕获过程异常: {e}")
        import traceback
        traceback.print_exc()
        capture.stop()
        sys.exit(1)

    print("\n[*] 正在生成隐私审计报告...\n")

    if detector is None:
        detector = SensitiveDataDetector()

    report = PrivacyReport(tracker, capture, detector, duration=duration)
    report.print_full()


def main():
    parser = argparse.ArgumentParser(
        prog="privacy-auditor",
        description="单进程级网络遥测隐私审计器：监控指定进程的网络出口流量并检测隐私数据外泄",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  privacy-auditor --pid 1234 -d 60            审计 PID 1234 进程 60 秒
  privacy-auditor -p svchost.exe -d 30        按进程名模糊匹配审计 30 秒
  privacy-auditor --list                      列出所有运行中的进程
  privacy-auditor --list chrome               查找包含 chrome 的进程
        """
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--pid", type=int, metavar="PID", help="目标进程 PID")
    group.add_argument("-p", "--process", metavar="NAME", help="目标进程名 (模糊匹配)")
    group.add_argument("--list", nargs="?", const="", metavar="KEYWORD",
                       help="列出运行中的进程 (可选关键字过滤)")

    parser.add_argument("-d", "--duration", type=int, default=30, metavar="SECONDS",
                        help="捕获时长（秒），默认 30。设为 0 则一直运行直到 Ctrl+C")
    parser.add_argument("-v", "--version", action="version", version="privacy-auditor 0.1.0")

    args = parser.parse_args()

    if args.list is not None:
        list_processes(args.list if args.list else None)
        return

    if not args.pid and not args.process:
        parser.print_help()
        print("\n[错误] 请指定 --pid 或 -p/--process")
        sys.exit(2)

    duration = max(0, args.duration)
    run_audit(pid=args.pid, process_name=args.process, duration=duration)


if __name__ == "__main__":
    main()
