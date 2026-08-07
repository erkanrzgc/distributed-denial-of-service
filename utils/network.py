import asyncio
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class NetworkInterface:
    name: str
    ip: str
    mac: str
    is_up: bool


def get_interfaces() -> list[NetworkInterface]:
    interfaces = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ip = ""
            mac = ""
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0].get("addr", "")
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get("addr", "")
            interfaces.append(NetworkInterface(
                name=iface, ip=ip, mac=mac,
                is_up=bool(ip)
            ))
    except ImportError:
        try:
            result = subprocess.run(
                ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                for entry in data:
                    ifname = entry.get("ifname", "unknown")
                    ip_addr = ""
                    mac_addr = ""
                    for addr in entry.get("addr_info", []):
                        if addr.get("family") == "inet":
                            ip_addr = addr.get("local", "")
                    if ip_addr:
                        mac_addr = entry.get("address", "")
                        interfaces.append(NetworkInterface(
                            name=ifname, ip=ip_addr, mac=mac_addr,
                            is_up=entry.get("operstate") == "UP"
                        ))
        except Exception as e:
            logger.warning("interface_detect_failed", error=str(e))
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                interfaces.append(NetworkInterface(
                    name="default", ip=ip, mac="unknown", is_up=True
                ))
            except Exception:
                interfaces.append(NetworkInterface(
                    name="lo", ip="127.0.0.1", mac="00:00:00:00:00:00", is_up=True
                ))

    return interfaces


def get_default_interface() -> Optional[NetworkInterface]:
    ifaces = get_interfaces()
    for iface in ifaces:
        if iface.is_up and iface.name not in ("lo", "loopback"):
            return iface
    for iface in ifaces:
        if iface.is_up:
            return iface
    return None


def resolve_host(host: str, port: int) -> tuple[str, int]:
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for addr in addrs:
            family, socktype, proto, canonname, sockaddr = addr
            ip = sockaddr[0]
            port = sockaddr[1]
            if family == socket.AF_INET:
                return (ip, port)
        raise socket.gaierror("no IPv4 address found")
    except socket.gaierror:
        return (host, port)


async def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def bandwidth_test(target: str, duration: float = 5.0) -> float:
    start = time.monotonic()
    total_bytes = 0
    try:
        reader, writer = await asyncio.open_connection(target, 80)
        payload = b"x" * 65536
        while time.monotonic() - start < duration:
            writer.write(payload)
            await writer.drain()
            total_bytes += len(payload)
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    elapsed = time.monotonic() - start
    return (total_bytes * 8) / elapsed / 1_000_000 if elapsed > 0 else 0.0
