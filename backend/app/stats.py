"""Packets/sec, bytes/sec timeline and protocol counts."""

from __future__ import annotations

from collections import Counter

KEEP_SECONDS = 600


class Stats:
    def __init__(self) -> None:
        self.buckets: dict[int, list[int]] = {}   # second -> [bytes, packets]
        self.protocols: Counter[str] = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self.latest = 0.0
        self.first: float | None = None

    def add(self, ts: float, length: int, category: str) -> None:
        sec = int(ts)
        b = self.buckets.get(sec)
        if b is None:
            b = self.buckets[sec] = [0, 0]
            if len(self.buckets) > KEEP_SECONDS * 2:
                self._prune()
        b[0] += length
        b[1] += 1
        self.protocols[category] += 1
        self.total_packets += 1
        self.total_bytes += length
        if ts > self.latest:
            self.latest = ts
        if self.first is None or ts < self.first:
            self.first = ts

    def _prune(self) -> None:
        cutoff = int(self.latest) - KEEP_SECONDS
        for sec in [s for s in self.buckets if s < cutoff]:
            del self.buckets[sec]

    def rate(self, now: float) -> tuple[float, float]:
        """(packets/s, bytes/s) for the last complete second."""
        b = self.buckets.get(int(now) - 1, [0, 0])
        return float(b[1]), float(b[0])

    def timeline(self, now: float, seconds: int = 60) -> list[list[float]]:
        end = int(now)
        return [[float(s), float(self.buckets.get(s, [0, 0])[0])]
                for s in range(end - seconds + 1, end + 1)]

    def file_timeline(self, max_points: int = 300) -> list[list[float]]:
        """Whole-capture timeline for an uploaded file, downsampled."""
        if not self.buckets:
            return []
        start, end = min(self.buckets), max(self.buckets)
        span = end - start + 1
        step = max(1, -(-span // max_points))
        out = []
        for s in range(start, end + 1, step):
            total = sum(self.buckets.get(x, [0, 0])[0] for x in range(s, min(s + step, end + 1)))
            out.append([float(s), total / step])
        return out

    def clear(self) -> None:
        self.__init__()
