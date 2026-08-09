import asyncio
import time
from collections import defaultdict, deque
from statistics import mean, stdev
from typing import Any, Optional

import structlog

from detection.base import BaseDetector
from core.events import EventType, event_bus

logger = structlog.get_logger(__name__)


class AnomalyDetector(BaseDetector):
    name = "anomaly"
    description = "Baseline-based anomaly detection for DDoS attack patterns"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._baseline: dict[str, float] = {}
        self._baseline_collected = False
        self._baseline_samples: list[dict] = []
        self._recent_metrics: deque[dict] = deque(maxlen=300)
        self._alerts: deque[dict] = deque(maxlen=100)
        self._anomaly_count = 0

    async def run(
        self,
        baseline_duration: int = 60,
        anomaly_threshold: float = 2.5,
        sensitivity: float = 1.5,
        **kwargs: Any,
    ) -> None:
        self._baseline_duration = baseline_duration
        self._anomaly_threshold = anomaly_threshold
        self._sensitivity = sensitivity
        logger.info("anomaly_detector_started", baseline_duration=baseline_duration)

        start_time = time.monotonic()

        while not self.session.is_stopped:
            await self.session._pause_event.wait()

            if not self._baseline_collected and time.monotonic() - start_time >= baseline_duration:
                self._build_baseline()

            if self._baseline_collected:
                metrics = self._get_current_metrics()
                self._recent_metrics.append(metrics)
                self._detect_anomalies(metrics)

            await asyncio.sleep(0.5)

    def feed_data(self, packets_per_sec: int, bytes_per_sec: int, connections: int, unique_ips: int) -> None:
        sample = {
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "connections": connections,
            "unique_ips": unique_ips,
            "time": time.monotonic(),
        }
        if not self._baseline_collected:
            self._baseline_samples.append(sample)

    def _build_baseline(self) -> None:
        if len(self._baseline_samples) < 10:
            logger.warning("baseline_insufficient", samples=len(self._baseline_samples))
            return

        for metric in ("packets_per_sec", "bytes_per_sec", "connections", "unique_ips"):
            values = [s[metric] for s in self._baseline_samples]
            self._baseline[f"{metric}_mean"] = mean(values) if values else 0
            self._baseline[f"{metric}_std"] = stdev(values) if len(values) > 1 else 1

        self._baseline_collected = True
        logger.info("baseline_established", baseline=self._baseline)

    def _get_current_metrics(self) -> dict[str, Any]:
        if self._recent_metrics:
            return self._recent_metrics[-1]
        return {"packets_per_sec": 0, "bytes_per_sec": 0, "connections": 0, "unique_ips": 0}

    def _detect_anomalies(self, metrics: dict[str, Any]) -> None:
        anomalies = []

        for metric in ("packets_per_sec", "bytes_per_sec", "connections", "unique_ips"):
            mean_key = f"{metric}_mean"
            std_key = f"{metric}_std"
            if mean_key not in self._baseline:
                continue

            mean = self._baseline[mean_key]
            std = self._baseline[std_key]
            current = metrics.get(metric, 0)

            if std > 0:
                z_score = (current - mean) / std
            elif current > mean * 3:
                z_score = self._anomaly_threshold + 1
            else:
                z_score = 0

            if abs(z_score) > self._anomaly_threshold:
                anomalies.append({
                    "metric": metric,
                    "value": current,
                    "baseline_mean": round(mean, 1),
                    "z_score": round(z_score, 2),
                    "severity": "high" if abs(z_score) > 4 else "medium",
                })

        if anomalies:
            self._anomaly_count += 1
            alert = {
                "time": time.time(),
                "anomalies": anomalies,
                "id": self._anomaly_count,
            }
            self._alerts.append(alert)
            self.session.update_stats(
                rate_hits=self._anomaly_count,
            )
            logger.warning("anomaly_detected", count=len(anomalies), metrics=[a["metric"] for a in anomalies])
            event_bus.publish_sync(EventType.DETECT_ANOMALY, event="anomaly",
                                    count=len(anomalies),
                                    metrics=[a["metric"] for a in anomalies])

    def get_alerts(self, limit: int = 20) -> list[dict]:
        return list(self._alerts)[-limit:]

    def get_baseline(self) -> dict:
        return dict(self._baseline)

    def get_stats(self) -> dict[str, Any]:
        return {
            "baseline_ready": self._baseline_collected,
            "baseline": dict(self._baseline) if self._baseline_collected else {},
            "anomalies_found": self._anomaly_count,
            "recent_alerts": len(self._alerts),
        }
