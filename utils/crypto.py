import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ProofOfWorkChallenge:
    challenge: str
    difficulty: int
    created_at: float

    def verify(self, solution: str) -> bool:
        if time.time() - self.created_at > 300:
            return False
        target = "0" * self.difficulty
        return hashlib.sha256(f"{self.challenge}:{solution}".encode()).hexdigest().startswith(target)

    @classmethod
    def create(cls, difficulty: int = 4) -> "ProofOfWorkChallenge":
        return cls(
            challenge=secrets.token_hex(16),
            difficulty=difficulty,
            created_at=time.time(),
        )

    def to_dict(self) -> dict:
        return {
            "challenge": self.challenge,
            "difficulty": self.difficulty,
        }


def solve_pow(challenge: ProofOfWorkChallenge) -> Optional[str]:
    target = "0" * challenge.difficulty
    nonce = 0
    max_iterations = 1000000
    prefix = challenge.challenge.encode()
    while nonce < max_iterations:
        candidate = str(secrets.randbits(32))
        if hashlib.sha256(prefix + candidate.encode()).hexdigest().startswith(target):
            return candidate
        nonce += 1
    return None


def generate_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(generate_hmac(key, message), signature)


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.blake2b(token.encode(), digest_size=32).hexdigest()
