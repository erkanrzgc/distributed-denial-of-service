import asyncio
import os
import subprocess
import time
from typing import Any

import structlog

from defense.base import BaseDefender

logger = structlog.get_logger(__name__)


class DynamicFirewall(BaseDefender):
    name = "dynamic_firewall"
    description = "Dynamic IP blacklisting via iptables/nftables integration"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._blocked_ips: set[str] = set()
        self._firewall_type = "iptables"
        self._blocked_count = 0
        self._is_root = os.geteuid() == 0
        self._check_firewall()

    def _check_firewall(self) -> None:
        if not self._is_root:
            logger.warning("firewall_no_root", message="Dynamic firewall requires root privileges for iptables")
            return
        try:
            result = subprocess.run(["which", "iptables"], capture_output=True, text=True)
            if result.returncode != 0:
                result = subprocess.run(["which", "nft"], capture_output=True, text=True)
                if result.returncode == 0:
                    self._firewall_type = "nftables"
                    logger.info("firewall_nftables_detected")
                else:
                    logger.warning("firewall_not_found")
                    self._is_root = False
                    return
            logger.info("firewall_ready", type=self._firewall_type)
        except Exception as e:
            logger.error("firewall_check_failed", error=str(e))
            self._is_root = False

    async def run(
        self,
        threshold_connections: int = 100,
        threshold_rate: int = 50,
        block_duration: int = 300,
        port: int = 0,
        **kwargs: Any,
    ) -> None:
        self._threshold_connections = threshold_connections
        self._threshold_rate = threshold_rate
        self._block_duration = block_duration
        self._port = port
        logger.info("dynamic_firewall_started", threshold=threshold_connections)

        try:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                await self._monitor_connections()
                self.session.update_stats(
                    blocked_count=len(self._blocked_ips),
                    passed_count=self._blocked_count,
                )
                await asyncio.sleep(1.0)
        finally:
            await self._unblock_all()

    def block_ip(self, ip: str, reason: str = "ddos") -> bool:
        if ip in self._blocked_ips:
            return False
        if not self._is_root:
            logger.info("would_block_ip", ip=ip, reason=reason)
            self._blocked_ips.add(ip)
            self._blocked_count += 1
            return True

        try:
            if self._firewall_type == "iptables":
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                if self._port:
                    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(self._port), "-j", "DROP"]
            else:
                cmd = ["nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"]

            subprocess.run(cmd, check=True, timeout=5, capture_output=True)
            self._blocked_ips.add(ip)
            self._blocked_count += 1
            logger.info("ip_blocked", ip=ip, reason=reason)
            if self._block_duration > 0:
                asyncio.get_event_loop().call_later(self._block_duration, self.unblock_ip, ip)
            return True
        except Exception as e:
            logger.error("block_failed", ip=ip, error=str(e))
            return False

    def unblock_ip(self, ip: str) -> bool:
        if ip not in self._blocked_ips:
            return False
        if not self._is_root:
            self._blocked_ips.discard(ip)
            return True

        try:
            if self._firewall_type == "iptables":
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                if self._port:
                    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(self._port), "-j", "DROP"]
            else:
                cmd = ["nft", "delete", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"]

            subprocess.run(cmd, check=True, timeout=5, capture_output=True)
            self._blocked_ips.discard(ip)
            logger.info("ip_unblocked", ip=ip)
            return True
        except Exception as e:
            logger.error("unblock_failed", ip=ip, error=str(e))
            return False

    async def _monitor_connections(self) -> None:
        try:
            result = subprocess.run(
                ["ss", "-tan", "state", "established"],
                capture_output=True, text=True, timeout=3
            )
            lines = result.stdout.strip().split("\n")[1:]
            if len(lines) > self._threshold_connections * 1.5:
                logger.warning("high_connection_count", count=len(lines))
        except Exception:
            pass

    async def _unblock_all(self) -> None:
        for ip in list(self._blocked_ips):
            self.unblock_ip(ip)
        self._blocked_ips.clear()

    def get_stats(self) -> dict[str, Any]:
        return {
            "blocked_count": len(self._blocked_ips),
            "total_blocked": self._blocked_count,
            "firewall_type": self._firewall_type,
            "is_root": self._is_root,
        }
