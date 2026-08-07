import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Optional

import structlog

from detection.base import BaseDetector
from utils.network import get_default_interface

logger = structlog.get_logger(__name__)


class TrafficMonitor(BaseDetector):
    name = "monitor"
    description = "Real-time network traffic monitoring and analysis"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._traffic_log: deque[dict] = deque(maxlen=1000)
        self._connections: dict[str, int] = defaultdict(int)
        self._stats = {
            "total_packets": 0, "total_bytes": 0,
            "packets_per_sec": 0, "bytes_per_sec": 0,
            "active_connections": 0, "unique_ips": 0,
            "tcp_packets": 0, "udp_packets": 0, "icmp_packets": 0,
            "alert_threshold": 5000,
        }
        self._last_check = time.monotonic()
        self._last_packets = 0
        self._last_bytes = 0

    async def run(
        self,
        interface: Optional[str] = None,
        alert_threshold: int = 5000,
        capture_filter: str = "",
        **kwargs: Any,
    ) -> None:
        self._alert_threshold = alert_threshold

        has_scapy = False
        try:
            from scapy.all import AsyncSniffer
            self._sniffer_class = AsyncSniffer
            has_scapy = True
        except ImportError:
            logger.warning("scapy_not_available", message="Packet capture disabled. Install with: pip install scapy")

        self._interface = interface or (get_default_interface().name if get_default_interface() else "eth0")
        logger.info("monitor_started", interface=self._interface, threshold=alert_threshold)



        if has_scapy:
            sniffer = self._sniffer_class(
                iface=self._interface,
                prn=self._process_packet,
                store=False,
                filter=capture_filter or "tcp or udp or icmp",
            )
            sniffer.start()

        try:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                self._calculate_rates()
                self._check_alerts()
                self.session.update_stats(**self._stats)
                await asyncio.sleep(0.25)
        finally:
            if has_scapy:
                sniffer.stop()

    def _process_packet(self, pkt: Any) -> None:
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            self._stats["total_packets"] += 1
            pkt_len = len(pkt)
            self._stats["total_bytes"] += pkt_len

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                self._stats["unique_ips"] = len(self._connections)
                self._connections[f"{src}->{dst}"] += 1

            if TCP in pkt:
                self._stats["tcp_packets"] += 1
            elif UDP in pkt:
                self._stats["udp_packets"] += 1
            elif ICMP in pkt:
                self._stats["icmp_packets"] += 1

            self._traffic_log.append({
                "time": time.time(),
                "size": pkt_len,
                "src": getattr(pkt[IP] if IP in pkt else None, "src", "?"),
                "dst": getattr(pkt[IP] if IP in pkt else None, "dst", "?"),
                "proto": "TCP" if TCP in pkt else ("UDP" if UDP in pkt else ("ICMP" if ICMP in pkt else "OTHER")),
            })
        except Exception:
            pass

    def _calculate_rates(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_check
        if elapsed > 0:
            self._stats["packets_per_sec"] = int((self._stats["total_packets"] - self._last_packets) / elapsed)
            self._stats["bytes_per_sec"] = int((self._stats["total_bytes"] - self._last_bytes) / elapsed)
            self._stats["active_connections"] = len(self._connections)
        self._last_packets = self._stats["total_packets"]
        self._last_bytes = self._stats["total_bytes"]
        self._last_check = now

    def _check_alerts(self) -> None:
        if self._stats["packets_per_sec"] > self._alert_threshold:
            logger.warning("high_traffic_alert", pps=self._stats["packets_per_sec"], threshold=self._alert_threshold)

    def get_top_ips(self, limit: int = 10) -> list[dict[str, Any]]:
        sorted_cons = sorted(self._connections.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"address": addr, "packets": count} for addr, count in sorted_cons]

    def get_recent_traffic(self, count: int = 50) -> list[dict]:
        return list(self._traffic_log)[-count:]

    def get_stats(self) -> dict[str, Any]:
        return dict(self._stats)
