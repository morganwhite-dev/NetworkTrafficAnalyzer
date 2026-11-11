from scapy.all import Ether

from app.parser import dissect, facts_from, layer_tree, row
from app.redact import find_secrets, mask_text
from app.textsafe import clean
from app.tlsinfo import client_hello_sni
from helpers import (
    SELF,
    arp_who_has,
    client_hello,
    dns_answer,
    dns_query,
    icmp_port_unreachable,
    tcp,
    udp,
)


def facts(pkt):
    raw = bytes(pkt)
    return facts_from(Ether(raw), 1.0, len(raw))


def test_tcp_syn_info_and_flags():
    f = facts(tcp(SELF, "140.82.112.3", 50000, 443, "S"))
    assert f.proto == "TCP"
    assert "[SYN]" in f.info and f.sport == 50000 and f.dport == 443
    assert f.tcp_flags & 0x02


def test_tls_client_hello_sni():
    f = facts(tcp(SELF, "140.82.112.3", 50000, 443, "PA", client_hello("github.com")))
    assert f.proto == "TLS"
    assert f.sni == "github.com"
    assert f.info == "Client Hello · github.com"


def test_sni_parser_rejects_garbage():
    assert client_hello_sni(b"\x16\x03\x01\x00\x05\x01\xff") is None
    assert client_hello_sni(b"") is None
    assert client_hello_sni(client_hello("ok.example")[:30]) is None


def test_http_request_masks_query_secrets():
    payload = b"GET /login?user=bob&password=hunter2 HTTP/1.1\r\nHost: shop.example\r\n\r\n"
    f = facts(tcp(SELF, "93.184.215.14", 50001, 80, "PA", payload))
    assert f.proto == "HTTP"
    assert "hunter2" not in f.info
    assert "password=••••" in f.info
    assert f.http_host == "shop.example"


def test_dns_query_and_answer():
    q = facts(dns_query("example.com"))
    assert q.proto == "DNS" and q.dns_query == ("example.com", "A")
    a = facts(dns_answer("example.com", "93.184.215.14"))
    assert a.dns_response and a.dns_answers == [("example.com", "93.184.215.14")]
    assert "→ 93.184.215.14" in a.info


def test_arp_and_quic_and_icmp_quote():
    f = facts(arp_who_has("192.168.1.77", "02:00:00:00:00:77", "192.168.1.9"))
    assert f.proto == "ARP" and f.arp_op == 1 and f.arp_pdst == "192.168.1.9"
    q = facts(udp(SELF, "142.250.80.46", 50000, 443, b"\xc3" + b"\x00" * 40))
    assert q.proto == "QUIC" and q.info == "QUIC Initial"
    i = facts(icmp_port_unreachable("192.168.1.9", SELF, "192.168.1.9", 161))
    assert i.icmp_type == 3 and i.quoted == ("udp", SELF, "192.168.1.9", 161)


def test_malformed_does_not_raise():
    f = facts_from(dissect(b"\x00" * 3, 1), 1.0, 3)
    assert f.proto in {"Other", "Malformed"}
    assert row(1, f)["len"] == 3


def test_layer_tree_offsets():
    pkt = Ether(bytes(tcp(SELF, "1.1.1.1", 1234, 80, "S")))
    tree = layer_tree(pkt)
    names = [layer["name"] for layer in tree]
    assert names[:3] == ["Ethernet", "IP", "TCP"]
    assert tree[0]["start"] == 0 and tree[0]["end"] == 14
    assert tree[1]["start"] == 14 and tree[1]["end"] == 34
    assert tree[2]["start"] == 34


def test_find_secrets_http_body_basic_and_ftp():
    body = b"POST /login HTTP/1.1\r\nHost: a\r\nAuthorization: Basic Ym9iOmh1bnRlcjI=\r\n\r\n" \
           b"user=bob&password=hunter2"
    found = find_secrets(body, 80)
    kinds = {s.kind for s in found}
    assert "HTTP Basic auth" in kinds and "HTTP form password" in kinds
    pw = next(s for s in found if s.kind == "HTTP form password")
    assert body[pw.start:pw.end] == b"hunter2"
    ftp = find_secrets(b"PASS s3cret\r\n", 21)
    assert ftp and b"PASS s3cret"[ftp[0].start:ftp[0].end] == b"s3cret"
    assert find_secrets(b"\xff\xfe garbage", 80) == []


def test_mask_text_and_clean():
    assert mask_text("GET /a?token=abc&x=1") == "GET /a?token=••••&x=1"
    assert clean("evil\x1b[31mred‮") == "evil[31mred"
    assert len(clean("x" * 500, 20)) == 20
