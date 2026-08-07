import hashlib
import time
from collections import deque
from typing import Any, Optional

import structlog

from detection.base import BaseDetector

logger = structlog.get_logger(__name__)


class FingerprintTracker(BaseDetector):
    name = "fingerprint"
    description = "Attack fingerprinting: identify and track attack patterns and signatures"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._similarity_threshold = 0.85
        self._group_timeout = 60
        self._known_attacks: dict[str, dict] = {}
        self._fingerprint_db: deque[dict] = deque(maxlen=500)
        self._active_attacks: dict[str, dict] = {}
        self._stats = {
            "fingerprints_created": 0,
            "known_attacks_detected": 0,
            "new_patterns": 0,
            "tracked_attacks": 0,
        }

    async def run(
        self,
        similarity_threshold: float = 0.85,
        group_timeout: int = 60,
        **kwargs: Any,
    ) -> None:
        self._similarity_threshold = similarity_threshold
        self._group_timeout = group_timeout
        logger.info("fingerprint_tracker_started")

        while not self.session.is_stopped:
            await self.session._pause_event.wait()
            self._cleanup_expired_attacks()
            self.session.update_stats(
                rate_hits=self._stats["tracked_attacks"],
            )
            await asyncio.sleep(1.0)

    def create_fingerprint(self, data: dict[str, Any]) -> dict[str, Any]:
        self._stats["fingerprints_created"] += 1

        fingerprint = {
            "id": hashlib.md5(str(data).encode()).hexdigest()[:12],
            "created_at": time.time(),
            "data": data,
            "hash": self._hash_features(data),
        }

        self._group_fingerprint(fingerprint)
        self._fingerprint_db.append(fingerprint)

        self._check_known_attacks(fingerprint)

        return fingerprint

    def _hash_features(self, data: dict[str, Any]) -> str:
        features = [
            str(data.get("packet_size_avg", 0)),
            str(data.get("rate", 0)),
            str(data.get("protocol", "")),
            str(data.get("port", 0)),
            str(data.get("flags", "")),
            str(data.get("ttl", 0)),
            str(data.get("window_size", 0)),
        ]
        return hashlib.sha256("|".join(features).encode()).hexdigest()[:16]

    def _group_fingerprint(self, fp: dict[str, Any]) -> None:
        for attack_id, attack in list(self._active_attacks.items()):
            similarity = self._calculate_similarity(fp, attack)
            if similarity >= self._similarity_threshold:
                attack["fingerprints"].append(fp)
                attack["last_seen"] = time.time()
                attack["count"] += 1
                return

        attack_id = f"attack_{len(self._active_attacks) + 1}"
        self._active_attacks[attack_id] = {
            "id": attack_id,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "fingerprints": [fp],
            "count": 1,
            "signature": fp["hash"],
            "data_summary": fp["data"],
        }
        self._stats["new_patterns"] += 1
        self._stats["tracked_attacks"] += 1

    def _calculate_similarity(self, fp: dict, attack: dict) -> float:
        if attack["signature"] == fp["hash"]:
            return 1.0

        data_a = fp["data"]
        data_b = attack["data_summary"]
        matches = 0
        total = 0

        for key in ("protocol", "port", "flags"):
            total += 1
            if str(data_a.get(key, "")) == str(data_b.get(key, "")):
                matches += 1

        for key in ("rate", "packet_size_avg"):
            total += 1
            va = data_a.get(key, 0)
            vb = data_b.get(key, 0)
            if max(va, vb) > 0 and abs(va - vb) / max(va, vb) < 0.2:
                matches += 1

        return matches / total if total > 0 else 0.0

    def _check_known_attacks(self, fp: dict[str, Any]) -> None:
        if fp["hash"] in self._known_attacks:
            self._known_attacks[fp["hash"]]["hit_count"] += 1
            self._known_attacks[fp["hash"]]["last_hit"] = time.time()
            self._stats["known_attacks_detected"] += 1
            logger.warning("known_attack_pattern", signature=fp["hash"],
                           data=self._known_attacks[fp["hash"]]["label"])

    def register_known_attack(self, signature: str, label: str, data: dict) -> None:
        self._known_attacks[signature] = {
            "label": label,
            "data": data,
            "hit_count": 0,
            "last_hit": 0,
            "registered_at": time.time(),
        }

    def _cleanup_expired_attacks(self) -> None:
        now = time.time()
        expired = [
            aid for aid, a in self._active_attacks.items()
            if now - a["last_seen"] > self._group_timeout
        ]
        for aid in expired:
            del self._active_attacks[aid]
            self._stats["tracked_attacks"] -= 1

    def get_active_attacks(self) -> list[dict]:
        attacks = []
        for aid, attack in self._active_attacks.items():
            attacks.append({
                "id": attack["id"],
                "count": attack["count"],
                "duration": time.time() - attack["first_seen"],
                "signature": attack["signature"],
                "last_seen": attack["last_seen"],
            })
        return sorted(attacks, key=lambda x: x["count"], reverse=True)

    def get_known_attacks(self) -> list[dict]:
        return [
            {"signature": sig, "label": data["label"], "hits": data["hit_count"]}
            for sig, data in self._known_attacks.items()
        ]

    def get_stats(self) -> dict[str, Any]:
        return {
            "fingerprints_created": self._stats["fingerprints_created"],
            "known_attacks_detected": self._stats["known_attacks_detected"],
            "new_patterns": self._stats["new_patterns"],
            "active_attacks": len(self._active_attacks),
        }
