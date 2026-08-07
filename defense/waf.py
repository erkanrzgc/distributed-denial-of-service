import re
from typing import Any, Optional

import structlog

from defense.base import BaseDefender

logger = structlog.get_logger(__name__)

SQL_INJECTION_PATTERNS = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", re.IGNORECASE),
    re.compile(r"\w*((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
    re.compile(r"((\%27)|(\'))\s*union", re.IGNORECASE),
    re.compile(r"exec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    re.compile(r"(?:--[^\n]*\n|/\*.*?\*/|#)", re.IGNORECASE),
    re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)", re.IGNORECASE),
    re.compile(r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)", re.IGNORECASE),
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<iframe.*?>", re.IGNORECASE),
    re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"((\%2E)|\.)((\%2E)|\.)((\%2F)|\/|(\%5C)|\\\\)", re.IGNORECASE),
    re.compile(r"\.\.\/|\.\.\\", re.IGNORECASE),
    re.compile(r"(\%00|\x00)", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|hosts)", re.IGNORECASE),
    re.compile(r"c:\\windows", re.IGNORECASE),
]

COMMAND_INJECTION = [
    re.compile(r"[;&|`$]\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh|python|perl|php|ruby)\b", re.IGNORECASE),
    re.compile(r"system\(", re.IGNORECASE),
    re.compile(r"exec\(", re.IGNORECASE),
    re.compile(r"eval\(", re.IGNORECASE),
]


class WAF(BaseDefender):
    name = "waf"
    description = "Web Application Firewall with SQLi, XSS, path traversal, and command injection detection"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._scan_sqli = True
        self._scan_xss = True
        self._scan_traversal = True
        self._scan_cmdi = True
        self._stats = {
            "total_checks": 0,
            "sqli_detected": 0,
            "xss_detected": 0,
            "traversal_detected": 0,
            "cmdi_detected": 0,
            "passed": 0,
        }

    async def run(
        self,
        scan_sqli: bool = True,
        scan_xss: bool = True,
        scan_traversal: bool = True,
        scan_cmdi: bool = True,
        **kwargs: Any,
    ) -> None:
        self._scan_sqli = scan_sqli
        self._scan_xss = scan_xss
        self._scan_traversal = scan_traversal
        self._scan_cmdi = scan_cmdi
        logger.info("waf_started", sqli=scan_sqli, xss=scan_xss)

        await self.session.wait_for_stop()

    def scan(self, content: str, source: str = "request") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if self._scan_sqli:
            for pattern in SQL_INJECTION_PATTERNS:
                match = pattern.search(content)
                if match:
                    findings.append({
                        "type": "SQL_INJECTION",
                        "pattern": pattern.pattern,
                        "match": match.group()[:50],
                        "source": source,
                    })
                    self._stats["sqli_detected"] += 1
                    logger.warning("waf_sqli_detected", source=source, match=match.group()[:50])
                    break

        if self._scan_xss:
            for pattern in XSS_PATTERNS:
                match = pattern.search(content)
                if match:
                    findings.append({
                        "type": "XSS",
                        "pattern": pattern.pattern,
                        "match": match.group()[:50],
                        "source": source,
                    })
                    self._stats["xss_detected"] += 1
                    logger.warning("waf_xss_detected", source=source, match=match.group()[:50])
                    break

        if self._scan_traversal:
            for pattern in PATH_TRAVERSAL_PATTERNS:
                match = pattern.search(content)
                if match:
                    findings.append({
                        "type": "PATH_TRAVERSAL",
                        "pattern": pattern.pattern,
                        "match": match.group()[:50],
                        "source": source,
                    })
                    self._stats["traversal_detected"] += 1
                    logger.warning("waf_traversal_detected", source=source, match=match.group()[:50])
                    break

        if self._scan_cmdi:
            for pattern in COMMAND_INJECTION:
                match = pattern.search(content)
                if match:
                    findings.append({
                        "type": "COMMAND_INJECTION",
                        "pattern": pattern.pattern,
                        "match": match.group()[:50],
                        "source": source,
                    })
                    self._stats["cmdi_detected"] += 1
                    logger.warning("waf_cmdi_detected", source=source, match=match.group()[:50])
                    break

        self._stats["total_checks"] += 1
        if not findings:
            self._stats["passed"] += 1

        return findings

    def scan_request(self, method: str, path: str, headers: dict, body: Optional[str] = None) -> list[dict[str, Any]]:
        findings = []
        findings.extend(self.scan(path, source=f"{method} {path}"))
        findings.extend(self.scan(" ".join(headers.values()), source="headers"))
        if body:
            findings.extend(self.scan(body, source="body"))
        return findings

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_checks": self._stats["total_checks"],
            "sqli_detected": self._stats["sqli_detected"],
            "xss_detected": self._stats["xss_detected"],
            "traversal_detected": self._stats["traversal_detected"],
            "cmdi_detected": self._stats["cmdi_detected"],
            "passed": self._stats["passed"],
        }
