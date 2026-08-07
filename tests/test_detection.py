import pytest
from detection.entropy import EntropyAnalyzer
from detection.fingerprint import FingerprintTracker
from core.session import Session


class TestEntropyAnalyzer:
    def test_ip_entropy_low(self):
        analyzer = EntropyAnalyzer(session=Session(), event_bus=None)
        entropy = analyzer._calculate_ip_entropy(["1.2.3.4", "1.2.3.4", "1.2.3.4", "1.2.3.4"])
        assert entropy == 0.0

    def test_ip_entropy_high(self):
        analyzer = EntropyAnalyzer(session=Session(), event_bus=None)
        entropy = analyzer._calculate_ip_entropy(["1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"])
        assert entropy >= 2.0

    def test_value_entropy(self):
        analyzer = EntropyAnalyzer(session=Session(), event_bus=None)
        entropy = analyzer._value_entropy(b"aaaaaaaa")
        assert entropy == 0.0

    def test_traffic_analysis_ddos(self):
        analyzer = EntropyAnalyzer(session=Session(), event_bus=None)
        result = analyzer.analyze_traffic(
            src_ips=["1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"],
            dst_ips=["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1"],
        )
        assert result["dst_entropy"] == 0.0
        assert any(a["type"] == "DDoS_LIKELY" for a in result["alerts"])

    def test_traffic_analysis_exfil(self):
        analyzer = EntropyAnalyzer(session=Session(), event_bus=None)
        result = analyzer.analyze_traffic(
            src_ips=["10.0.0.1"],
            dst_ips=["1.2.3.4"],
            payloads=[b"\x00\xff\x12\xab\xcd\xef\x99\x88"],
        )
        assert result["payload_entropy"] > 2.0

    def test_body_data_analysis(self):
        analyzer = EntropyAnalyzer(session=Session(), event_bus=None)
        result = analyzer.analyze_body_data(b"Hello World")
        assert result["is_plaintext"]


class TestFingerprintTracker:
    def test_create_fingerprint(self):
        tracker = FingerprintTracker(session=Session(), event_bus=None)
        fp = tracker.create_fingerprint({"rate": 1000, "protocol": "TCP", "port": 443})
        assert fp["id"]
        assert fp["hash"]
        assert tracker._stats["fingerprints_created"] == 1

    def test_group_similar_fingerprints(self):
        tracker = FingerprintTracker(session=Session(), event_bus=None)
        fp1 = tracker.create_fingerprint({"rate": 1000, "protocol": "TCP", "port": 443, "packet_size_avg": 64, "flags": "SYN"})
        fp2 = tracker.create_fingerprint({"rate": 1050, "protocol": "TCP", "port": 443, "packet_size_avg": 64, "flags": "SYN"})
        assert tracker._stats["fingerprints_created"] == 2
        assert tracker._stats["new_patterns"] == 1

    def test_known_attack_detection(self):
        tracker = FingerprintTracker(session=Session(), event_bus=None)
        data = {"rate": 5000, "protocol": "UDP", "port": 53}
        fp = tracker.create_fingerprint(data)
        tracker.register_known_attack(fp["hash"], "DNS Amplification", data)
        fp2 = tracker.create_fingerprint(data)
        assert tracker._stats["known_attacks_detected"] >= 1
