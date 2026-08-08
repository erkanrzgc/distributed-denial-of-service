import asyncio
import ssl
import time
from typing import Any, Optional

import aiohttp
import structlog

logger = structlog.get_logger(__name__)

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9090]

TECH_SIGNATURES = {
    "Cloudflare": {"Server": "cloudflare", "cf-ray": None},
    "nginx": {"Server": "nginx"},
    "Apache": {"Server": "Apache/"},
    "AWS CloudFront": {"Server": "CloudFront", "x-amz-cf-id": None},
    "Varnish": {"Server": "varnish", "X-Varnish": None},
    "IIS": {"Server": "Microsoft-IIS"},
    "LiteSpeed": {"Server": "LiteSpeed", "X-LiteSpeed": None},
    "Caddy": {"Server": "Caddy"},
    "Express": {"X-Powered-By": "Express"},
    "Next.js": {"x-powered-by": "Next.js", "x-nextjs": None},
    "Django": {"X-Framework": "Django"},
    "Laravel": {"Set-Cookie": "laravel_session"},
    "Fastly": {"X-Served-By": "cache-", "Server": "fastly"},
    "Akamai": {"X-Akamai-Transformed": None, "Server": "AkamaiGHost"},
    "Imperva": {"X-CDN": "Incapsula", "X-Imperva": None},
    "AWS WAF": {"x-amzn-RequestId": None},
}

WAF_SIGNATURES = {
    "Cloudflare WAF": {"cf-chl-bypass": None, "__cfruid": None, "cf_clearance": None},
    "AWS WAF": {"x-amzn-waf": None},
    "Akamai": {"X-Akamai-Request-ID": None},
    "Imperva/Incapsula": {"X-CDN": "Incapsula", "X-I-Cache": None},
    "Sucuri": {"X-Sucuri-ID": None, "Server": "Sucuri"},
    "ModSecurity": {"Server": "mod_security", "X-Mod-Security": None},
    "F5 BIG-IP": {"Server": "BIG-IP", "X-WA-Info": None},
}


class TargetProfile:
    def __init__(self):
        self.url: str = ""
        self.host: str = ""
        self.ip: str = ""
        self.port: int = 80
        self.is_https: bool = False
        self.status_code: int = 0
        self.response_time: float = 0.0
        self.server: str = ""
        self.powered_by: str = ""
        self.tech_stack: list[str] = []
        self.waf: list[str] = []
        self.cdn: list[str] = []
        self.open_ports: list[int] = []
        self.headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}
        self.tls_version: str = ""
        self.suggested_attacks: list[dict] = []
        self.rate_limited: bool = False
        self.errors: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "https": self.is_https,
            "status": self.status_code,
            "response_time_ms": round(self.response_time * 1000),
            "server": self.server,
            "tech_stack": self.tech_stack,
            "waf": self.waf,
            "cdn": self.cdn,
            "open_ports": self.open_ports,
            "tls": self.tls_version,
            "rate_limited": self.rate_limited,
            "suggested_attacks": self.suggested_attacks,
            "errors": self.errors,
        }


async def scan_target(url: str, scan_ports: bool = True, timeout: float = 10.0) -> TargetProfile:
    profile = TargetProfile()
    profile.url = url

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    profile.host = parsed.hostname or url
    profile.port = parsed.port or (443 if parsed.scheme == "https" else 80)
    profile.is_https = parsed.scheme == "https"

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=5)
    timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=5)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
        t_start = time.monotonic()
        try:
            async with session.get(url, allow_redirects=True, max_redirects=5) as resp:
                profile.response_time = time.monotonic() - t_start
                profile.status_code = resp.status
                profile.headers = dict(resp.headers)
                profile.ip = resp.connection.transport.get_extra_info("peername")[0] if resp.connection else ""

                for key, vals in resp.headers.items():
                    if isinstance(vals, str):
                        vals = [vals]
                    for val in vals if isinstance(vals, (list, tuple)) else [vals]:
                        for tech, sigs in TECH_SIGNATURES.items():
                            if key.lower() in sigs and (sigs[key.lower()] is None or str(sigs[key.lower()]).lower() in str(val).lower()):
                                if tech not in profile.tech_stack:
                                    profile.tech_stack.append(tech)
                        for waf, sigs in WAF_SIGNATURES.items():
                            if key.lower() in sigs and (sigs[key.lower()] is None or str(sigs[key.lower()]).lower() in str(val).lower()):
                                if waf not in profile.waf:
                                    profile.waf.append(waf)

                profile.server = resp.headers.get("Server", resp.headers.get("server", ""))
                profile.powered_by = resp.headers.get("X-Powered-By", resp.headers.get("x-powered-by", ""))

                profile.cookies = {k: v.value for k, v in resp.cookies.items()}

                if resp.status == 429 or resp.status == 403:
                    profile.rate_limited = True
                    if resp.status == 403:
                        retry_check = await _check_rate_limit(url, session)
                        if retry_check:
                            profile.rate_limited = True

                await resp.read()
        except asyncio.TimeoutError:
            profile.errors.append("timeout")
            profile.status_code = 0
        except aiohttp.ClientConnectorError as e:
            profile.errors.append(f"connection_refused: {e}")
            profile.status_code = 0
        except aiohttp.ServerDisconnectedError:
            profile.errors.append("server_disconnected")
            profile.status_code = 0
        except Exception as e:
            profile.errors.append(f"error: {e}")
            profile.status_code = 0

    _detect_tls(profile)
    _generate_suggestions(profile)

    if scan_ports and profile.ip:
        await _scan_ports(profile, timeout)

    return profile


def _detect_tls(profile: TargetProfile) -> None:
    if not profile.is_https:
        return
    try:
        import socket
        ctx = ssl.create_default_context()
        with socket.create_connection((profile.host, profile.port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=profile.host) as ssock:
                profile.tls_version = ssock.version() or "unknown"
                cert = ssock.getpeercert()
                if cert:
                    profile.errors.append(f"tls_ok: {profile.tls_version}")
    except Exception as e:
        profile.errors.append(f"tls_error: {e}")


async def _scan_ports(profile: TargetProfile, timeout: float) -> None:
    sem = asyncio.Semaphore(20)

    async def check_port(port: int) -> None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(profile.ip, port), timeout=min(2.0, timeout / 2)
                )
                profile.open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    tasks = [asyncio.create_task(check_port(p)) for p in COMMON_PORTS]
    await asyncio.gather(*tasks, return_exceptions=True)
    profile.open_ports.sort()


async def _check_rate_limit(url: str, session: aiohttp.ClientSession) -> bool:
    for _ in range(3):
        try:
            async with session.get(url) as resp:
                if resp.status == 429:
                    return True
            await asyncio.sleep(0.1)
        except Exception:
            return False
    return False


def _generate_suggestions(profile: TargetProfile) -> None:
    suggestions = []

    if 80 in profile.open_ports or profile.port == 80:
        suggestions.append({
            "attack": "slowloris",
            "reason": "HTTP open — Slowloris eats connections",
            "priority": "high",
            "config": {"port": 80, "connections": 200},
        })
        suggestions.append({
            "attack": "http_flood",
            "reason": "HTTP server — flood it",
            "priority": "high",
            "config": {"port": 80, "rate": 1000, "method": "GET"},
        })

    if 443 in profile.open_ports or profile.is_https:
        suggestions.append({
            "attack": "http_flood",
            "reason": "HTTPS open — high-rate flood",
            "priority": "high",
            "config": {"port": 443, "rate": 500, "method": "GET"},
        })
        suggestions.append({
            "attack": "slow_read",
            "reason": "HTTPS — slow read drains threads",
            "priority": "medium",
            "config": {"port": 443, "connections": 100, "read_delay": 5.0},
        })

    if profile.status_code == 200:
        suggestions.append({
            "attack": "layer7",
            "reason": "App alive — layer7 bypass",
            "priority": "medium",
            "config": {"rate": 50, "concurrent": 100},
        })

    if not profile.waf:
        suggestions.append({
            "attack": "syn_flood",
            "reason": "no WAF — SYN flood the stack",
            "priority": "high",
            "config": {"port": profile.port, "rate": 10000, "spoof": True},
        })
        suggestions.append({
            "attack": "udp_flood",
            "reason": "no WAF — UDP eats bandwidth",
            "priority": "medium",
            "config": {"port": 53, "rate": 5000, "packet_size": 512},
        })
    else:
        suggestions.append({
            "attack": "http_flood",
            "reason": f"WAF: {', '.join(profile.waf)} — rotate UA",
            "priority": "high",
            "config": {"port": profile.port, "rate": 500, "method": "GET"},
        })

    if "nginx" in profile.tech_stack or "Apache" in profile.tech_stack:
        for s in suggestions:
            if s["attack"] == "slowloris":
                s["priority"] = "high"
                s["reason"] += " (threaded)"

    if profile.server and "cloudflare" in profile.server.lower():
        suggestions.append({
            "attack": "http_flood",
            "reason": "Cloudflare — high conn + random UA",
            "priority": "high",
            "config": {"port": profile.port, "rate": 2000, "method": "GET"},
        })

    profile.suggested_attacks = sorted(suggestions, key=lambda x: (
        0 if x["priority"] == "high" else (1 if x["priority"] == "medium" else 2)
    ))
