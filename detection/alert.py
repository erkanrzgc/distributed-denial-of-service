import asyncio
import json
import smtplib
import time
from email.mime.text import MIMEText
from typing import Any, Optional

import aiohttp
import structlog

from detection.base import BaseDetector
from core.events import EventType, event_bus

logger = structlog.get_logger(__name__)


class AlertSystem(BaseDetector):
    name = "alert"
    description = "Alert system with webhook, email, and Slack integration"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._alert_queue: asyncio.Queue = asyncio.Queue()
        self._stats = {
            "alerts_sent": 0,
            "webhooks_sent": 0,
            "emails_sent": 0,
            "slack_sent": 0,
            "errors": 0,
        }
        self._recent_alerts: list[dict] = []

    async def run(
        self,
        webhook_url: Optional[str] = None,
        email_to: Optional[str] = None,
        email_from: Optional[str] = None,
        smtp_host: Optional[str] = None,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        slack_webhook: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self._webhook_url = webhook_url
        self._email_to = email_to
        self._email_from = email_from
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._smtp_user = smtp_user
        self._smtp_pass = smtp_pass
        self._slack_webhook = slack_webhook

        event_bus.subscribe(EventType.DETECT_ALERT, self._on_alert_event)
        event_bus.subscribe(EventType.DEFENSE_ALERT, self._on_alert_event)
        event_bus.subscribe(EventType.DETECT_ANOMALY, self._on_alert_event)

        logger.info("alert_system_started", webhook=bool(webhook_url), email=bool(email_to), slack=bool(slack_webhook))

        try:
            while not self.session.is_stopped:
                await self.session._pause_event.wait()
                await self._process_queue()
                self.session.update_stats(
                    packets_sent=self._stats["alerts_sent"],
                )
                await asyncio.sleep(0.2)
        finally:
            event_bus.unsubscribe(EventType.DETECT_ALERT, self._on_alert_event)
            event_bus.unsubscribe(EventType.DEFENSE_ALERT, self._on_alert_event)
            event_bus.unsubscribe(EventType.DETECT_ANOMALY, self._on_alert_event)

    def _on_alert_event(self, **data: Any) -> None:
        self._alert_queue.put_nowait({
            "time": time.time(),
            "event": data.get("event", "unknown"),
            "data": data,
        })

    def send_alert(self, title: str, message: str, severity: str = "warning", metadata: Optional[dict] = None) -> None:
        self._alert_queue.put_nowait({
            "time": time.time(),
            "title": title,
            "message": message,
            "severity": severity,
            "metadata": metadata or {},
        })

    async def _process_queue(self) -> None:
        while not self._alert_queue.empty():
            try:
                alert = self._alert_queue.get_nowait()
                await self._dispatch_alert(alert)
            except asyncio.QueueEmpty:
                break

    async def _dispatch_alert(self, alert: dict) -> None:
        self._stats["alerts_sent"] += 1
        self._recent_alerts.append(alert)
        if len(self._recent_alerts) > 100:
            self._recent_alerts = self._recent_alerts[-100:]

        title = alert.get("title", alert.get("event", "DDoS Alert"))
        message = alert.get("message", json.dumps(alert.get("data", {}), default=str))
        severity = alert.get("severity", "warning")

        tasks = []
        if self._webhook_url:
            tasks.append(self._send_webhook(title, message, severity))
        if self._slack_webhook:
            tasks.append(self._send_slack(title, message, severity))
        if self._email_to and self._smtp_host:
            tasks.append(self._send_email(title, message))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                self._stats["errors"] += 1
                logger.error("alert_dispatch_failed", error=str(r))

    async def _send_webhook(self, title: str, message: str, severity: str) -> None:
        async with aiohttp.ClientSession() as session:
            payload = {"title": title, "message": message, "severity": severity, "timestamp": time.time()}
            async with session.post(self._webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status < 400:
                    self._stats["webhooks_sent"] += 1

    async def _send_slack(self, title: str, message: str, severity: str) -> None:
        colors = {"info": "#36a64f", "warning": "#ffcc00", "critical": "#ff0000"}
        color = colors.get(severity, "#ffcc00")
        payload = {
            "attachments": [{
                "title": title,
                "text": message,
                "color": color,
                "ts": int(time.time()),
            }]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(self._slack_webhook, json=payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status < 400:
                    self._stats["slack_sent"] += 1

    async def _send_email(self, title: str, message: str) -> None:
        try:
            msg = MIMEText(message)
            msg["Subject"] = f"[DDoS Toolkit] {title}"
            msg["From"] = self._email_from
            msg["To"] = self._email_to

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._smtp_send, msg)
        except Exception as e:
            logger.error("email_send_failed", error=str(e))

    def _smtp_send(self, msg: MIMEText) -> None:
        with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as server:
            server.starttls()
            if self._smtp_user:
                server.login(self._smtp_user, self._smtp_pass)
            server.send_message(msg)
            self._stats["emails_sent"] += 1

    def get_recent_alerts(self, limit: int = 20) -> list[dict]:
        return self._recent_alerts[-limit:]

    def get_stats(self) -> dict[str, Any]:
        return {
            "alerts_sent": self._stats["alerts_sent"],
            "webhooks_sent": self._stats["webhooks_sent"],
            "emails_sent": self._stats["emails_sent"],
            "slack_sent": self._stats["slack_sent"],
            "errors": self._stats["errors"],
            "queue_size": self._alert_queue.qsize(),
        }
