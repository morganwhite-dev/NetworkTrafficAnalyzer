import io

from scapy.all import TCP, rdpcap

from app.store import RECORD_OVERHEAD, PacketStore
from helpers import SELF, tcp


def make_store(n=5, max_bytes=10_000_000):
    s = PacketStore(max_bytes)
    for i in range(n):
        raw = bytes(tcp(SELF, "1.1.1.1", 1000 + i, 443, "S", b"x" * 200))
        s.add(1700000000.0 + i * 0.5, raw, 1, {"id": 0})
    return s


def test_ids_and_recent_rows():
    s = make_store(5)
    assert len(s) == 5
    rows = s.recent_rows(3)
    assert [r["id"] for r in rows] == [3, 4, 5]
    assert s.get(1) is not None and s.get(99) is None


def test_byte_cap_evicts_oldest():
    one = len(bytes(tcp(SELF, "1.1.1.1", 1, 443, "S", b"x" * 200))) + RECORD_OVERHEAD
    s = make_store(10, max_bytes=one * 4)
    assert len(s) == 4
    assert s.get(1) is None and s.get(10) is not None
    assert s.evicted == 6


def test_export_round_trip_full_and_headers_only():
    s = make_store(3)
    pkts = rdpcap(io.BytesIO(s.export_pcap()))
    assert len(pkts) == 3
    assert pkts[0][TCP].sport == 1000
    assert abs(float(pkts[1].time) - 1700000000.5) < 1e-5
    short = rdpcap(io.BytesIO(s.export_pcap(headers_only=True)))
    assert all(len(bytes(p)) <= 128 for p in short)
    assert short[0].wirelen == len(s.get(1).raw)
