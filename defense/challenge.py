import asyncio
import time
from typing import Any

import structlog

from defense.base import BaseDefender
from utils.crypto import ProofOfWorkChallenge

logger = structlog.get_logger(__name__)


class ChallengeDefender(BaseDefender):
    name = "challenge"
    description = "Proof-of-Work / CAPTCHA-like challenge-response defense"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._pending_challenges: dict[str, ProofOfWorkChallenge] = {}
        self._verified_ips: dict[str, float] = {}
        self._stats = {"challenges_sent": 0, "challenges_passed": 0, "challenges_failed": 0}

    async def run(
        self,
        difficulty: int = 4,
        challenge_ttl: int = 300,
        grace_period: int = 600,
        **kwargs: Any,
    ) -> None:
        self._difficulty = difficulty
        self._challenge_ttl = challenge_ttl
        self._grace_period = grace_period
        logger.info("challenge_defender_started", difficulty=difficulty)

        while not self.session.is_stopped:
            await self.session._pause_event.wait()
            self._cleanup_expired()
            self.session.update_stats(
                challenges_sent=self._stats["challenges_sent"],
            )
            await asyncio.sleep(1.0)

    def challenge_ip(self, client_ip: str) -> dict[str, Any]:
        if client_ip in self._verified_ips:
            if time.time() - self._verified_ips[client_ip] < self._grace_period:
                return {"challenged": False, "reason": "already_verified"}

        challenge = ProofOfWorkChallenge.create(difficulty=self._difficulty)
        self._pending_challenges[client_ip] = challenge
        self._stats["challenges_sent"] += 1
        return {
            "challenged": True,
            "challenge": challenge.challenge,
            "difficulty": challenge.difficulty,
        }

    def verify_solution(self, client_ip: str, solution: str) -> dict[str, Any]:
        challenge = self._pending_challenges.get(client_ip)
        if not challenge:
            return {"verified": False, "reason": "no_challenge"}

        if challenge.verify(solution):
            del self._pending_challenges[client_ip]
            self._verified_ips[client_ip] = time.time()
            self._stats["challenges_passed"] += 1
            return {"verified": True, "reason": "ok"}
        else:
            self._stats["challenges_failed"] += 1
            return {"verified": False, "reason": "invalid_solution"}

    def _cleanup_expired(self) -> None:
        now = time.time()
        expired = [ip for ip, c in self._pending_challenges.items() if now - c.created_at > self._challenge_ttl]
        for ip in expired:
            del self._pending_challenges[ip]
            self._stats["challenges_failed"] += 1

        expired_verified = [ip for ip, t in self._verified_ips.items() if now - t > self._grace_period]
        for ip in expired_verified:
            del self._verified_ips[ip]

    def is_verified(self, client_ip: str) -> bool:
        return client_ip in self._verified_ips

    def get_stats(self) -> dict[str, Any]:
        return {
            "challenges_sent": self._stats["challenges_sent"],
            "challenges_passed": self._stats["challenges_passed"],
            "challenges_failed": self._stats["challenges_failed"],
            "pending": len(self._pending_challenges),
            "verified": len(self._verified_ips),
        }
