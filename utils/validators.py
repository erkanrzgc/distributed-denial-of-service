import re
import socket
import urllib.parse
from typing import Optional


def validate_target(target: str) -> tuple[bool, Optional[str], Optional[str]]:
    if not target or not target.strip():
        return False, None, "Target is empty"

    target = target.strip()

    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ip_pattern.match(target):
        return True, target, None

    url_match = re.match(r"^https?://", target)
    if url_match:
        try:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname
        except Exception:
            return False, None, "Invalid URL format"
    else:
        host = target.split(":")[0]

    if not host or "." not in host:
        return False, None, f"Not a valid hostname: {host}"

    hostname_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if not hostname_pattern.match(host):
        if not ip_pattern.match(host):
            return False, None, f"Invalid hostname: {host}"

    try:
        socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
        return True, host, None
    except socket.gaierror:
        return False, host, f"Cannot resolve {host} — check the address or your network"

    return True, host, None


def format_error(host: str, error: str) -> str:
    return f"[red]✗ {host}[/] — {error}"
