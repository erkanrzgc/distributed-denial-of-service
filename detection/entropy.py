import math
from collections import Counter
from typing import Any, Optional

import structlog

from detection.base import BaseDetector

logger = structlog.get_logger(__name__)


class EntropyAnalyzer(BaseDetector):
    name = "entropy"
    description = "Traffic entropy analysis for detecting DDoS attacks and data exfiltration"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._ddos_threshold = 0.3
        self._exfil_threshold = 7.0
        self._window_size = 60
        self._src_entropy_history: list[float] = []
        self._dst_entropy_history: list[float] = []
        self._payload_entropy_history: list[float] = []
        self._stats = {
            "checks": 0,
            "high_entropy_events": 0,
            "low_entropy_events": 0,
            "exfil_alerts": 0,
            "ddos_alerts": 0,
        }

    async def run(
        self,
        ddos_threshold: float = 0.3,
        exfil_threshold: float = 7.0,
        window_size: int = 60,
        **kwargs: Any,
    ) -> None:
        self._ddos_threshold = ddos_threshold
        self._exfil_threshold = exfil_threshold
        self._window_size = window_size
        logger.info("entropy_analyzer_started", ddos_threshold=ddos_threshold, exfil_threshold=exfil_threshold)

        await self.session.wait_for_stop()

    def analyze_traffic(
        self,
        src_ips: list[str],
        dst_ips: list[str],
        payloads: Optional[list[bytes]] = None,
    ) -> dict[str, Any]:
        self._stats["checks"] += 1

        src_entropy = self._calculate_ip_entropy(src_ips)
        dst_entropy = self._calculate_ip_entropy(dst_ips)
        payload_entropy = self._calculate_payload_entropy(payloads) if payloads else 0.5

        self._src_entropy_history.append(src_entropy)
        self._dst_entropy_history.append(dst_entropy)
        self._payload_entropy_history.append(payload_entropy)

        result = {
            "src_entropy": round(src_entropy, 3),
            "dst_entropy": round(dst_entropy, 3),
            "payload_entropy": round(payload_entropy, 3),
            "alerts": [],
        }

        if dst_entropy < self._ddos_threshold:
            self._stats["ddos_alerts"] += 1
            self._stats["low_entropy_events"] += 1
            result["alerts"].append({"type": "DDoS_LIKELY", "reason": "Low destination entropy suggests focused attack"})
            logger.warning("ddos_entropy_alert", dst_entropy=dst_entropy)

        if payload_entropy > self._exfil_threshold:
            self._stats["exfil_alerts"] += 1
            self._stats["high_entropy_events"] += 1
            result["alerts"].append({"type": "EXFILTRATION_POSSIBLE", "reason": "High payload entropy (encrypted/encoded data)"})
            logger.warning("exfil_entropy_alert", payload_entropy=payload_entropy)

        if src_entropy < 0.5 and dst_entropy > 2.0:
            result["alerts"].append({"type": "SCAN_ACTIVITY", "reason": "Few sources scanning many destinations"})

        self.session.update_stats(
            packets_sent=self._stats["checks"],
            rate_hits=len(result["alerts"]),
        )

        return result

    def analyze_body_data(self, body: bytes) -> dict[str, Any]:
        entropy = self._value_entropy(body)
        self._stats["checks"] += 1
        return {
            "entropy": round(entropy, 3),
            "is_encrypted": entropy > 6.5,
            "is_compressed": 5.0 < entropy < 6.5,
            "is_plaintext": entropy < 5.0,
            "alert": entropy > self._exfil_threshold,
        }

    @staticmethod
    def _calculate_ip_entropy(ips: list[str]) -> float:
        if not ips:
            return 0.0
        counter = Counter(ips)
        total = len(ips)
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _calculate_payload_entropy(payloads: list[bytes]) -> float:
        if not payloads:
            return 0.0
        entropies = [EntropyAnalyzer._value_entropy(p) for p in payloads if p]
        return sum(entropies) / len(entropies) if entropies else 0.0

    @staticmethod
    def _value_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def get_stats(self) -> dict[str, Any]:
        return {
            "checks": self._stats["checks"],
            "high_entropy_events": self._stats["high_entropy_events"],
            "low_entropy_events": self._stats["low_entropy_events"],
            "exfil_alerts": self._stats["exfil_alerts"],
            "ddos_alerts": self._stats["ddos_alerts"],
            "recent_src_entropy": self._src_entropy_history[-1] if self._src_entropy_history else 0,
            "recent_dst_entropy": self._dst_entropy_history[-1] if self._dst_entropy_history else 0,
        }
