from datetime import datetime
from pathlib import Path
from typing import Optional

LOG_DIR = Path("logs")


def create_log(target: str, mode: str, module_name: str) -> Path:
    import urllib.parse
    parsed = urllib.parse.urlparse(target) if "://" in target else type("P", (), {"hostname": target})()
    host = getattr(parsed, "hostname", None) or target
    clean = host.replace("/", "_").replace("\\", "_").replace(":", "_")[:64]
    folder = LOG_DIR / clean
    folder.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = folder / f"{module_name}_{ts}.log"
    path.write_text(f"# {mode}: {module_name}\n# Target: {target}\n# Started: {datetime.now().isoformat()}\n\n")
    return path


def append_log(path: Path, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    try:
        with open(path, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def write_session_summary(path: Path, session_data: dict) -> None:
    lines = [
        "",
        f"# Completed: {datetime.now().isoformat()}",
        f"# Status: {session_data.get('status', 'unknown')}",
        f"# Duration: {session_data.get('duration', 0):.1f}s",
        f"# Requests: {session_data.get('packets_sent', 0)}",
        f"# Errors: {session_data.get('errors', 0)}",
        f"# Success: {session_data.get('success_rate', 0):.1f}%",
        f"# Bandwidth: {session_data.get('bandwidth_mbps', 0):.2f} Mbps",
    ]
    try:
        with open(path, "a") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass
