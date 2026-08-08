import math
import random


class Histogram:
    def __init__(self, max_samples: int = 200_000) -> None:
        self._samples: list[float] = []
        self._count = 0
        self._max_samples = max_samples
        self._sorted_cache: list[float] | None = None

    @property
    def count(self) -> int:
        return self._count

    @property
    def lo(self) -> float:
        return min(self._samples) if self._samples else 0.0

    @property
    def hi(self) -> float:
        return max(self._samples) if self._samples else 0.0

    @property
    def mean(self) -> float:
        return sum(self._samples) / len(self._samples) if self._samples else 0.0

    def add(self, value: float) -> None:
        self._sorted_cache = None
        self._count += 1
        if len(self._samples) < self._max_samples:
            self._samples.append(value)
        else:
            idx = random.randint(0, self._count - 1)
            if idx < self._max_samples:
                self._samples[idx] = value

    def _sorted(self) -> list[float]:
        if self._sorted_cache is None:
            self._sorted_cache = sorted(self._samples)
        return self._sorted_cache

    def pct(self, p: float) -> float:
        data = self._sorted()
        if not data:
            return 0.0
        n = len(data) - 1
        k = (p / 100.0) * n
        f = int(k)
        c = min(f + 1, n)
        if f == c:
            return data[f]
        return data[f] * (c - k) + data[c] * (k - f)

    def reset(self) -> None:
        self._samples.clear()
        self._count = 0
        self._sorted_cache = None

    def stats(self) -> dict[str, float]:
        return {
            "count": self.count,
            "min": round(self.lo, 1),
            "max": round(self.hi, 1),
            "mean": round(self.mean, 1),
            "p50": round(self.pct(50), 1),
            "p75": round(self.pct(75), 1),
            "p90": round(self.pct(90), 1),
            "p95": round(self.pct(95), 1),
            "p99": round(self.pct(99), 1),
            "p999": round(self.pct(99.9), 1),
        }
