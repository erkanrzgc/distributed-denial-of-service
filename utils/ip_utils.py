import ipaddress
import random
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


def random_ip() -> str:
    while True:
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        if not any(ip.startswith(p) for p in ("127.", "10.", "172.16.", "192.168.", "0.", "224.", "240.")):
            return ip


def random_ip_range(base_ip: str, mask: int = 24) -> str:
    try:
        network = ipaddress.ip_network(f"{base_ip}/{mask}", strict=False)
        hosts = list(network.hosts())
        if hosts:
            return str(random.choice(hosts))
    except ValueError:
        pass
    return random_ip()


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def geo_lookup(ip: str) -> Optional[dict]:
    try:
        import json
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "ddos-toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "asn": data.get("as", "Unknown"),
            }
    except Exception as e:
        logger.debug("geo_lookup_failed", ip=ip, error=str(e))
        return None


def parse_target(target: str) -> tuple[str, Optional[int], bool]:
    import re
    is_url = target.startswith(("http://", "https://"))
    host = target
    port = None
    if is_url:
        match = re.match(r"https?://([^:/]+)(?::(\d+))?(/.*)?", target)
        if match:
            host = match.group(1)
            port_str = match.group(2)
            port = int(port_str) if port_str else (443 if target.startswith("https") else 80)
    else:
        parts = target.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])
    return host, port, is_url
