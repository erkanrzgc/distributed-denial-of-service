import pytest
import math
from defense.waf import WAF
from defense.data_guard import DataGuard
from defense.rate_limiter import SlidingWindow, TokenBucket
from core.session import Session


class TestWAF:
    def test_sqli_detection(self):
        waf = WAF(session=Session(), event_bus=None)
        findings = waf.scan("SELECT * FROM users WHERE id = 1 OR 1=1 --")
        sqli = [f for f in findings if f["type"] == "SQL_INJECTION"]
        assert len(sqli) > 0

    def test_xss_detection(self):
        waf = WAF(session=Session(), event_bus=None)
        findings = waf.scan("<script>alert('xss')</script>")
        xss = [f for f in findings if f["type"] == "XSS"]
        assert len(xss) > 0

    def test_path_traversal(self):
        waf = WAF(session=Session(), event_bus=None)
        findings = waf.scan("../../../etc/passwd")
        traversal = [f for f in findings if f["type"] == "PATH_TRAVERSAL"]
        assert len(traversal) > 0

    def test_clean_input(self):
        waf = WAF(session=Session(), event_bus=None)
        findings = waf.scan("Hello World")
        assert len(findings) == 0

    def test_request_scan(self):
        waf = WAF(session=Session(), event_bus=None)
        findings = waf.scan_request(
            method="GET",
            path="/search?q=1' OR '1'='1",
            headers={"User-Agent": "Mozilla/5.0"},
            body=None,
        )
        assert len(findings) > 0


class TestDataGuard:
    def test_entropy_calculation(self):
        guard = DataGuard(session=Session(), event_bus=None)
        entropy_low = guard._calculate_entropy(b"aaaaaaaaaaaaaaaaaaaa")
        entropy_high = guard._calculate_entropy(b"x\x00\xff\xfe\xab\x12\x99\xcc")
        assert entropy_high > entropy_low

    def test_pii_detection(self):
        guard = DataGuard(session=Session(), event_bus=None)
        result = guard.scan_body(b"Contact: test@example.com, CC: 4111-1111-1111-1111")
        assert not result["allowed"]
        pii_types = [f["type"] for f in result["findings"]]
        assert any("PII_EMAIL" in t for t in pii_types) or any("PII_CREDIT_CARD" in t for t in pii_types)

    def test_oversized_body(self):
        guard = DataGuard(session=Session(), event_bus=None)
        guard._max_body_size = 10
        result = guard.scan_body(b"x" * 100)
        assert not result["allowed"]
        assert result["reason"] == "oversized"

    def test_clean_body(self):
        guard = DataGuard(session=Session(), event_bus=None)
        result = guard.scan_body(b"Hello World")
        assert result["allowed"]
        assert len(result["findings"]) == 0

    def test_sensitive_headers(self):
        guard = DataGuard(session=Session(), event_bus=None)
        result = guard.scan_headers({"Authorization": "Bearer secret123", "Content-Type": "application/json"})
        assert any("SENSITIVE_HEADER" in f["type"] for f in result.get("findings", []))


class TestRateLimiter:
    def test_token_bucket(self):
        bucket = TokenBucket(rate=10, capacity=10)
        for _ in range(10):
            assert bucket.consume()
        assert not bucket.consume()

    def test_sliding_window(self):
        window = SlidingWindow(max_requests=5, window_secs=10)
        for _ in range(5):
            assert window.allow("1.2.3.4")
        assert not window.allow("1.2.3.4")

    def test_sliding_window_different_ips(self):
        window = SlidingWindow(max_requests=5, window_secs=10)
        for _ in range(5):
            assert window.allow("1.2.3.4")
        assert window.allow("5.6.7.8")
