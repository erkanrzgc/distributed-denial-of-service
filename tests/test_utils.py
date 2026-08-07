import pytest
from utils.crypto import ProofOfWorkChallenge, generate_hmac, verify_hmac, hash_token
from utils.ip_utils import parse_target, is_private_ip


class TestCrypto:
    def test_pow_challenge(self):
        challenge = ProofOfWorkChallenge.create(difficulty=2)
        assert challenge.difficulty == 2
        assert len(challenge.challenge) > 0

        solution = f"{challenge.challenge}:test"
        import hashlib
        while not hashlib.sha256(solution.encode()).hexdigest().startswith("00"):
            challenge = ProofOfWorkChallenge.create(difficulty=2)
            solution = f"{challenge.challenge}:{hash(challenge.challenge) % 100000}"

    def test_pow_verify(self):
        challenge = ProofOfWorkChallenge.create(difficulty=1)
        assert not challenge.verify("invalid")

    def test_hmac(self):
        key = b"secret"
        msg = b"hello"
        sig = generate_hmac(key, msg)
        assert verify_hmac(key, msg, sig)
        assert not verify_hmac(key, msg, "bad")

    def test_hash_token(self):
        token = hash_token("my-token")
        assert len(token) == 64
        assert token != "my-token"


class TestIPUtils:
    def test_parse_target_url(self):
        host, port, is_url = parse_target("https://example.com:8443/path")
        assert host == "example.com"
        assert port == 8443
        assert is_url

    def test_parse_target_ip(self):
        host, port, is_url = parse_target("10.0.0.1:8080")
        assert host == "10.0.0.1"
        assert port == 8080
        assert not is_url

    def test_parse_target_plain(self):
        host, port, is_url = parse_target("example.com")
        assert host == "example.com"
        assert port is None

    def test_private_ip(self):
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("10.0.0.1")
        assert not is_private_ip("8.8.8.8")
        assert is_private_ip("127.0.0.1")
