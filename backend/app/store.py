"""Byte-capped ring buffer of captured packets, plus PCAP export."""

from __future__ import annotations

import io
import struct
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from .parser import HEADERS_FALLBACK

RECORD_OVERHEAD = 200  # rough per-record bookkeeping cost, so tiny packets still count


@dataclass(slots=True)
class Record:
    id: int
    ts: float
    raw: bytes
    linktype: int
    row: dict[str, Any]
    secrets: list[tuple[int, int]] = field(default_factory=list)  # absolute byte ranges
    header_len: int = HEADERS_FALLBACK  # where the payload starts (end of the last header)


def _headers_only(rec: Record) -> bytes:
    """The packet cut at the payload offset, with every detected secret range zeroed."""
    data = bytearray(rec.raw[: rec.header_len])
    for start, end in rec.secrets:
        if start < len(data):
            data[start:min(end, len(data))] = bytes(min(end, len(data)) - start)
    return bytes(data)


class PacketStore:
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self._records: OrderedDict[int, Record] = OrderedDict()
        self._bytes = 0
        self._next_id = 1
        self.evicted = 0

    def __len__(self) -> int:
        return len(self._records)

    @property
    def size_bytes(self) -> int:
        return self._bytes

    def add(self, ts: float, raw: bytes, linktype: int, row: dict[str, Any],
            secrets: list[tuple[int, int]] | None = None,
            header_len: int | None = None) -> Record:
        hl = HEADERS_FALLBACK if header_len is None else header_len
        rec = Record(self._next_id, ts, raw, linktype, row, secrets or [], max(0, hl))
        row["id"] = rec.id
        self._next_id += 1
        self._records[rec.id] = rec
        self._bytes += len(raw) + RECORD_OVERHEAD
        while self._bytes > self.max_bytes and self._records:
            _, old = self._records.popitem(last=False)
            self._bytes -= len(old.raw) + RECORD_OVERHEAD
            self.evicted += 1
        return rec

    def get(self, pid: int) -> Record | None:
        return self._records.get(pid)

    def recent_rows(self, limit: int) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        out: list[dict[str, Any]] = []
        for rec in reversed(self._records.values()):
            out.append(rec.row)
            if len(out) >= limit:
                break
        out.reverse()
        return out

    def clear(self) -> None:
        self._records.clear()
        self._bytes = 0
        self.evicted = 0

    def export_pcap(self, headers_only: bool = False) -> bytes:
        """Classic libpcap file (microsecond timestamps).

        ``headers_only`` keeps each packet up to the end of its last parsed header
        (link, network, transport) and drops the payload. Detected secret ranges are zeroed
        as well, so a secret can never survive even if a header range overlaps it. The full
        export is byte-for-byte what was captured.

        A capture session uses one link type (the store is cleared when the
        interface changes); records with a different link type are skipped.
        """
        buf = io.BytesIO()
        records = list(self._records.values())
        linktype = records[0].linktype if records else 1
        snaplen = 262144
        buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for rec in records:
            if rec.linktype != linktype:
                continue
            data = _headers_only(rec) if headers_only else rec.raw
            sec = int(rec.ts)
            usec = int(round((rec.ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            buf.write(struct.pack("<IIII", sec, usec, len(data), len(rec.raw)))
            buf.write(data)
        return buf.getvalue()
