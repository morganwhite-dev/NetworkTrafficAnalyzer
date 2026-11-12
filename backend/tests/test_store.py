import io

import pytest
from scapy.all import IP, TCP, rdpcap

from app.config import Settings
from app.geoip import GeoResolver
from app.pipeline import Pipeline
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
    assert all(len(bytes(p)) == 54 for p in short)  # Ethernet + IP + TCP, no payload
    assert short[0].wirelen == len(s.get(1).raw)


# --- "Headers only" must never carry payload or secrets ---------------------------------

LEAKS = [
    ("ftp", 21, b"USER alice\r\nPASS hunter2secret\r\n", [b"hunter2secret", b"PASS"]),
    ("http-query", 80, b"GET /login?password=hunter2q&x=1 HTTP/1.1\r\nHost: a.example\r\n\r\n",
     [b"hunter2q", b"GET /login"]),
    ("basic-auth", 80, b"GET / HTTP/1.1\r\nHost: a.example\r\n"
     b"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n", [b"dXNlcjpwYXNzd29yZA", b"Basic"]),
]


@pytest.fixture
def pipe(tmp_path):
    cfg = Settings()
    cfg.data_dir = tmp_path
    p = Pipeline(cfg, GeoResolver("off", cfg.geo_db, tmp_path))
    p.mode = "file"
    yield p
    p.close()


@pytest.mark.parametrize(("name", "dport", "payload", "forbidden"), LEAKS,
                         ids=[leak[0] for leak in LEAKS])
def test_headers_only_export_drops_payload_and_secrets(pipe, name, dport, payload, forbidden):
    pipe.process_now(bytes(tcp(SELF, "93.184.215.14", 50000, dport, "PA", payload)), 1.0, 1, 0)
    rec = pipe.store.get(1)
    assert rec.secrets, "parser should have flagged a secret"
    full = pipe.store.export_pcap()
    assert payload in full  # the full export is unchanged
    out = pipe.store.export_pcap(headers_only=True)
    for needle in forbidden:
        assert needle not in out
    pkt = rdpcap(io.BytesIO(out))[0]
    assert pkt[IP].dst == "93.184.215.14" and pkt[TCP].dport == dport  # headers survive
    assert pkt[TCP].sport == 50000
    assert pkt.wirelen == len(rec.raw)  # original length still recorded
    assert len(bytes(pkt)) == rec.header_len == 54


def test_headers_only_keeps_tcp_options_and_cuts_exactly_at_payload():
    raw = bytes(tcp(SELF, "1.1.1.1", 1, 80, "PA", b"PAYLOAD") )
    s = PacketStore(10_000_000)
    s.add(1.0, raw, 1, {"id": 0}, [], len(raw) - len(b"PAYLOAD"))
    out = rdpcap(io.BytesIO(s.export_pcap(headers_only=True)))[0]
    assert bytes(out) == raw[:-7]


def test_headers_only_zeroes_secret_ranges_even_inside_header_span():
    raw = b"A" * 20 + b"SECRET" + b"B" * 20
    s = PacketStore(10_000_000)
    s.add(1.0, raw, 1, {"id": 0}, [(20, 26)], 40)  # a range overlapping the kept bytes
    out = s.export_pcap(headers_only=True)
    assert b"SECRET" not in out
    assert out.endswith(b"A" * 20 + b"\x00" * 6 + b"B" * 14)


def test_secret_ranges_follow_captured_bytes_when_snaplen_truncated(pipe):
    payload = b"USER a\r\nPASS hunter2secret\r\n"
    pkt = bytes(tcp(SELF, "93.184.215.14", 50000, 21, "PA", payload))
    pipe.process_now(pkt, 1.0, 1, len(pkt) + 500)  # wire length larger than what was captured
    rec = pipe.store.get(1)
    start, end = rec.secrets[0]
    assert rec.raw[start:end] == b"hunter2secret"
    assert b"hunter2secret" not in pipe.store.export_pcap(headers_only=True)


def test_unparsed_packet_falls_back_to_fixed_header_length():
    s = PacketStore(10_000_000)
    s.add(1.0, b"\xde\xad" * 100, 1, {"id": 0})
    out = rdpcap(io.BytesIO(s.export_pcap(headers_only=True)))[0]
    assert len(bytes(out)) == 54
