import asyncio
import time
from collections import deque
from typing import Any, Optional

import aiohttp
from aiohttp import web
import structlog

from defense.base import BaseDefender

logger = structlog.get_logger(__name__)


class ReverseProxy(BaseDefender):
    name = "reverse_proxy"
    description = "Defensive reverse proxy with rate limiting, WAF, and data guard"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._backend_session: Optional[aiohttp.ClientSession] = None
        self._stats = {
            "requests": 0, "blocked": 0, "passed": 0, "errors": 0,
            "waf_triggers": 0, "rate_hits": 0,
        }
        self._rate_limiter_cache: dict[str, deque] = {}
        self._blocked_ips: set[str] = set()

    async def run(
        self,
        listen: str = "0.0.0.0:8080",
        backend: str = "http://localhost:3000",
        rate_limit: int = 100,
        rate_window: int = 60,
        max_body_size: int = 10485760,
        **kwargs: Any,
    ) -> None:
        host, port_str = listen.rsplit(":", 1) if ":" in listen else (listen, "8080")
        port = int(port_str)
        self._backend_url = backend.rstrip("/")
        self._rate_limit = rate_limit
        self._rate_window = rate_window
        self._max_body_size = max_body_size

        from collections import deque
        self._rate_limiter_cache: dict[str, deque] = {}

        self._backend_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=200, force_close=True),
        )

        self._app = web.Application(client_max_size=max_body_size)
        self._app.router.add_route("*", "/{path:.*}", self._handle_request)
        self._app["proxy"] = self

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host, port)
        await site.start()
        logger.info("reverse_proxy_started", listen=f"{host}:{port}", backend=backend)

        try:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                self.session.update_stats(
                    packets_sent=self._stats["requests"],
                    blocked_count=self._stats["blocked"],
                    passed_count=self._stats["passed"],
                    errors=self._stats["errors"],
                    waf_triggers=self._stats["waf_triggers"],
                    rate_hits=self._stats["rate_hits"],
                )
                await asyncio.sleep(0.5)
        finally:
            await self._backend_session.close()
            if self._runner:
                await self._runner.cleanup()

    async def _handle_request(self, request: web.Request) -> web.Response:
        client_ip = request.remote

        if client_ip in self._blocked_ips:
            self._stats["blocked"] += 1
            return web.Response(status=403, text="Access Denied")

        if not self._check_rate_limit(client_ip):
            self._stats["rate_hits"] += 1
            self._stats["blocked"] += 1
            self._blocked_ips.add(client_ip)
            return web.Response(status=429, text="Rate Limited")

        waf_result = self._check_waf(request)
        if waf_result:
            self._stats["waf_triggers"] += 1
            self._stats["blocked"] += 1
            logger.warning("waf_triggered", ip=client_ip, rule=waf_result)
            return web.Response(status=403, text="Forbidden")

        self._stats["requests"] += 1
        self._stats["passed"] += 1

        target_url = self._backend_url + request.path_qs
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host",)}
        headers["X-Forwarded-For"] = client_ip
        headers["X-Real-IP"] = client_ip
        headers["Host"] = self._backend_url.split("://", 1)[1].split(":", 1)[0]

        try:
            body = await request.read()
            async with self._backend_session.request(
                request.method, target_url,
                headers=headers, data=body,
                allow_redirects=False,
            ) as resp:
                response_body = await resp.read()
                return web.Response(
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=response_body,
                )
        except asyncio.TimeoutError:
            self._stats["errors"] += 1
            return web.Response(status=504, text="Gateway Timeout")
        except Exception as e:
            self._stats["errors"] += 1
            logger.error("proxy_error", error=str(e))
            return web.Response(status=502, text="Bad Gateway")

    def _check_rate_limit(self, ip: str) -> bool:
        from collections import deque
        now = time.monotonic()
        if ip not in self._rate_limiter_cache:
            self._rate_limiter_cache[ip] = deque()
        window = self._rate_limiter_cache[ip]
        while window and now - window[0] > self._rate_window:
            window.popleft()
        if len(window) >= self._rate_limit:
            return False
        window.append(now)
        return True

    def _check_waf(self, request: web.Request) -> Optional[str]:
        from urllib.parse import unquote
        path = unquote(request.path_qs).lower()
        headers_str = " ".join(str(v) for v in request.headers.values()).lower()

        sql_patterns = ["union select", "or 1=1", "' or '", "drop table", "-- ", "/*", "exec(", "sleep("]
        xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "<img", "<svg", "alert("]
        traversal_patterns = ["../", "..\\", "/etc/passwd", "cmd.exe", "c:\\windows", "/bin/"]
        cmdi_patterns = ["; ls", "| cat", "& dir", "`id`", "$(whoami)"]

        for pattern in sql_patterns + xss_patterns + traversal_patterns + cmdi_patterns:
            if pattern in path or pattern in headers_str:
                return pattern

        return None

    def get_stats(self) -> dict[str, Any]:
        return {
            "requests": self._stats["requests"],
            "blocked": self._stats["blocked"],
            "passed": self._stats["passed"],
            "errors": self._stats["errors"],
            "waf_triggers": self._stats["waf_triggers"],
            "rate_hits": self._stats["rate_hits"],
            "active_blocks": len(self._blocked_ips),
        }
