import json
import math
import re
from collections import Counter
from typing import Any, Optional

import structlog

from defense.base import BaseDefender

logger = structlog.get_logger(__name__)

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b\+?[\d\-\(\)\.]{7,}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "api_key": re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*[\S]+"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
}

SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "api_key", "apikey", "private",
    "credentials", "database_url", "connection_string", "access_key",
    "ssh_key", "certificate", "authorization", "bearer",
]


class DataGuard(BaseDefender):
    name = "data_guard"
    description = "Data leak protection: PII scanning, entropy analysis, body size limits"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._max_body_size = 10485760
        self._entropy_threshold = 5.5
        self._scan_pii = True
        self._scan_headers = True
        self._stats = {
            "bodies_scanned": 0,
            "pii_detected": 0,
            "high_entropy": 0,
            "oversized": 0,
            "sensitive_headers": 0,
            "blocked": 0,
            "total_bytes_scanned": 0,
        }

    async def run(
        self,
        max_body_size: int = 10485760,
        entropy_threshold: float = 5.5,
        scan_pii: bool = True,
        scan_headers: bool = True,
        **kwargs: Any,
    ) -> None:
        self._max_body_size = max_body_size
        self._entropy_threshold = entropy_threshold
        self._scan_pii = scan_pii
        self._scan_headers = scan_headers
        logger.info("data_guard_started", max_body= max_body_size, entropy=entropy_threshold)

        await self.session.wait_for_stop()

    def scan_body(self, body: bytes, content_type: Optional[str] = None) -> dict[str, Any]:
        result = {
            "allowed": True,
            "reason": "ok",
            "findings": [],
        }

        self._stats["bodies_scanned"] += 1
        self._stats["total_bytes_scanned"] += len(body)

        if len(body) > self._max_body_size:
            self._stats["oversized"] += 1
            self._stats["blocked"] += 1
            result["allowed"] = False
            result["reason"] = "oversized"
            result["findings"].append({"type": "OVERSIZED", "size": len(body), "limit": self._max_body_size})
            return result

        entropy = self._calculate_entropy(body)
        if entropy > self._entropy_threshold:
            self._stats["high_entropy"] += 1
            result["findings"].append({"type": "HIGH_ENTROPY", "entropy": entropy, "threshold": self._entropy_threshold})
            logger.warning("high_entropy_detected", entropy=entropy)

        if self._scan_pii:
            try:
                text = body.decode("utf-8", errors="ignore")
                pii_findings = self._scan_pii_patterns(text)
                if pii_findings:
                    self._stats["pii_detected"] += len(pii_findings)
                    result["findings"].extend(pii_findings)
                    self._stats["blocked"] += 1
                    result["allowed"] = False
                    result["reason"] = "pii_leak"
                    logger.warning("pii_detected_in_body", count=len(pii_findings),
                                   types=[f["type"] for f in pii_findings])
            except Exception as e:
                logger.debug("pii_scan_error", error=str(e))

        return result

    def scan_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        result = {
            "allowed": True,
            "reason": "ok",
            "findings": [],
        }

        if not self._scan_headers:
            return result

        try:
            headers_str = json.dumps(headers) if isinstance(headers, dict) else str(headers)
        except (TypeError, ValueError):
            headers_str = str(headers)

        for keyword in SENSITIVE_KEYWORDS:
            if keyword.lower() in headers_str.lower():
                self._stats["sensitive_headers"] += 1
                result["findings"].append({"type": "SENSITIVE_HEADER", "keyword": keyword, "location": "headers"})

        if self._scan_pii:
            pii_findings = self._scan_pii_patterns(headers_str)
            if pii_findings:
                self._stats["pii_detected"] += len(pii_findings)
                result["findings"].extend(pii_findings)
                result["allowed"] = False
                result["reason"] = "pii_in_headers"

        return result

    def _scan_pii_patterns(self, text: str) -> list[dict[str, Any]]:
        findings = []
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "type": f"PII_{pii_type.upper()}",
                    "count": len(matches),
                    "examples": list(set(str(m) for m in matches[:3])),
                })
        return findings

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def get_stats(self) -> dict[str, Any]:
        return {
            "bodies_scanned": self._stats["bodies_scanned"],
            "pii_detected": self._stats["pii_detected"],
            "high_entropy": self._stats["high_entropy"],
            "oversized": self._stats["oversized"],
            "sensitive_headers": self._stats["sensitive_headers"],
            "blocked": self._stats["blocked"],
            "total_bytes_scanned": self._stats["total_bytes_scanned"],
        }

