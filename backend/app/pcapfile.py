"""Treat .pcap/.pcapng files as hostile input.

1. Check the magic bytes ourselves (Scapy would happily gunzip a file).
2. Normalise the file in a separate process with a wall-clock timeout:
   records are size-capped, timestamps clamped, one link type kept, and the
   result rewritten as a plain libpcap file.
3. The main process only ever reads that normalised file.
"""

from __future__ import annotations

import multiprocessing as mp
import struct
import time
from pathlib import Path
from typing import Any

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",   # microsecond
    b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",   # nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MIN_TS = 946684800.0          # 2000-01-01


class PcapError(ValueError):
    pass


def check_magic(head: bytes) -> str:
    magic = head[:4]
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise PcapError("Not a pcap or pcapng file (bad magic bytes).")


def _normalize(src: str, dst: str, max_packets: int, max_record: int) -> dict[str, Any]:
    from scapy.utils import RawPcapReader  # imported in the child only

    max_ts = time.time() + 86400
    stats = {"packets": 0, "skipped": 0, "linktype": None, "first": None, "last": None,
             "truncated": False}
    last_ts = None
    with open(dst, "wb") as out:
        reader = RawPcapReader(src)
        try:
            header_written = False
            for data, meta in reader:
                if stats["packets"] >= max_packets:
                    stats["truncated"] = True
                    break
                if hasattr(meta, "linktype"):            # pcapng
                    linktype = int(meta.linktype)
                    resol = getattr(meta, "tsresol", 1_000_000) or 1_000_000
                    ts = ((int(meta.tshigh) << 32) | int(meta.tslow)) / resol
                    wirelen = int(getattr(meta, "wirelen", len(data)) or len(data))
                else:
                    linktype = int(reader.linktype)
                    div = 1_000_000_000 if getattr(reader, "nano", False) else 1_000_000
                    ts = int(meta.sec) + int(meta.usec) / div
                    wirelen = int(meta.wirelen)
                if stats["linktype"] is None:
                    stats["linktype"] = linktype
                if linktype != stats["linktype"] or len(data) > max_record or not data:
                    stats["skipped"] += 1
                    continue
                if not (MIN_TS <= ts <= max_ts):
                    ts = last_ts if last_ts is not None else MIN_TS
                last_ts = ts
                if not header_written:
                    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144,
                                          stats["linktype"]))
                    header_written = True
                sec = int(ts)
                usec = min(999_999, int(round((ts - sec) * 1_000_000)))
                wirelen = max(wirelen, len(data))
                out.write(struct.pack("<IIII", sec, usec, len(data), min(wirelen, 2**31)))
                out.write(data)
                stats["packets"] += 1
                stats["first"] = ts if stats["first"] is None else min(stats["first"], ts)
                stats["last"] = ts if stats["last"] is None else max(stats["last"], ts)
        finally:
            reader.close()
    if stats["packets"] == 0:
        raise PcapError("The file has no readable packets.")
    return stats


def _child(src: str, dst: str, max_packets: int, max_record: int, q: mp.Queue) -> None:
    try:
        q.put(("ok", _normalize(src, dst, max_packets, max_record)))
    except PcapError as exc:
        q.put(("error", str(exc)))
    except Exception as exc:  # noqa: BLE001
        q.put(("error", f"Could not read the capture file ({type(exc).__name__})."))


def normalize_in_child(src: Path, dst: Path, max_packets: int, max_record: int,
                       timeout: float) -> dict[str, Any]:
    with open(src, "rb") as fh:
        check_magic(fh.read(4))
    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    proc = ctx.Process(target=_child, args=(str(src), str(dst), max_packets, max_record, q),
                       daemon=True)
    proc.start()
    deadline = time.monotonic() + timeout
    result = None
    while time.monotonic() < deadline:
        try:
            result = q.get(timeout=0.25)
            break
        except Exception:  # noqa: BLE001 - queue.Empty
            if not proc.is_alive() and q.empty():
                break
    proc.join(timeout=1)
    if proc.is_alive():
        proc.kill()
        proc.join()
    if result is None:
        raise PcapError("Reading the capture file took too long or crashed; it was skipped.")
    status, payload = result
    if status != "ok":
        raise PcapError(payload)
    return payload


def iter_normalized(path: Path):
    """Yield (ts, raw, wirelen, linktype) from a file written by _normalize."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            return
        linktype = struct.unpack("<I", header[20:24])[0]
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, usec, caplen, wirelen = struct.unpack("<IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield sec + usec / 1_000_000, data, wirelen, linktype
