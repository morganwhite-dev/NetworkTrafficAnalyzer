import random
import string

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP, Ether

from app.config import Settings
from app.detectors import entropy, registrable
from app.geoip import GeoResolver
from app.pipeline import Pipeline
from helpers import (
    GW,
    MAC_GW,
    MAC_SELF,
    MAC_TV,
    SELF,
    arp_reply,
    dns_query,
    tcp,
)

T0 = 1_700_000_000.0
TV = "192.168.1.77"


@pytest.fixture
def pipe(tmp_path):
    s = Settings()
    s.data_dir = tmp_path
    p = Pipeline(s, GeoResolver("off", s.geo_db, tmp_path))
    p.mode = "file"
    yield p
    p.close()


def feed(p, pkt, ts, wirelen=0):
    p.process_now(bytes(pkt), ts, 1, wirelen)


def kinds(p):
    return {a.kind: a for a in p.alerts.items}


def test_port_scan_from_lan_device(pipe):
    for i, port in enumerate(range(20, 80)):
        ts = T0 + i * 0.05
        feed(pipe, tcp(TV, SELF, 40000, port, "S", smac=MAC_TV, dmac=MAC_SELF), ts)
        feed(pipe, tcp(SELF, TV, port, 40000, "RA", smac=MAC_SELF, dmac=MAC_TV), ts + 0.001)
    pipe.engine.advance(T0 + 6)
    alert = kinds(pipe)["port_scan"]
    assert alert.severity == "high" and alert.hosts[0] == TV
    assert "ports in 10 s" in alert.reason
    assert pipe.hosts.hosts[TV].severity == "high"


def test_normal_browsing_is_not_a_scan(pipe):
    for i in range(40):
        dst = f"140.82.{i}.3"
        ts = T0 + i * 0.1
        feed(pipe, tcp(SELF, dst, 50000 + i, 443, "S"), ts)
        feed(pipe, tcp(dst, SELF, 443, 50000 + i, "SA", smac=MAC_GW, dmac=MAC_SELF), ts + 0.02)
    pipe.engine.advance(T0 + 20)
    assert "port_scan" not in kinds(pipe) and "host_sweep" not in kinds(pipe)


def test_bandwidth_hog_and_spike(pipe):
    hog = "93.184.215.14"
    # 60 s of quiet background browsing (~40 KB/s) to establish a baseline.
    for s in range(60):
        for k in range(4):
            dst = f"151.101.{k}.1"
            feed(pipe, tcp(dst, SELF, 443, 50000 + k, "A", smac=MAC_GW, dmac=MAC_SELF),
                 T0 + s + k * 0.2, wirelen=10_000)
    # Then one host pulls ~4 MB/s for 20 s (large segments, like macOS LRO captures).
    for s in range(60, 80):
        for k in range(64):
            feed(pipe, tcp(hog, SELF, 443, 51000, "A", smac=MAC_GW, dmac=MAC_SELF),
                 T0 + s + k / 64, wirelen=64_000)
    pipe.engine.advance(T0 + 82)
    found = kinds(pipe)
    assert found["bandwidth_hog"].severity == "high"
    assert found["bandwidth_hog"].hosts == [hog]
    assert found["bandwidth_hog"].detail["share"] > 0.6
    assert found["traffic_spike"].severity == "medium"
    view = pipe.hosts.netview(T0 + 80)
    assert view["internet"][0]["ip"] == hog and view["internet"][0]["severity"] == "high"
    assert view["self"]["ip"] == SELF        # inferred in file mode


def test_gateway_arp_spoof(pipe):
    pipe.hosts.configure({SELF}, ["192.168.1.0/24"], GW)
    feed(pipe, arp_reply(GW, MAC_GW), T0)
    feed(pipe, arp_reply(TV, MAC_TV), T0 + 0.5)
    feed(pipe, arp_reply(GW, MAC_TV), T0 + 1)
    alert = kinds(pipe)["arp_spoof"]
    assert alert.severity == "high"
    assert alert.hosts == [GW, TV]
    assert MAC_TV in alert.reason


def test_dns_tunnel_pattern(pipe):
    rng = random.Random(7)
    for i in range(35):
        sub = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(30))
        feed(pipe, dns_query(f"{sub}.tunnel-example.net"), T0 + i * 0.5)
    alert = kinds(pipe)["dns_tunnel"]
    assert alert.severity == "medium" and "tunnel-example.net" in alert.reason


def test_cdn_names_do_not_trigger_dns_alert(pipe):
    for i in range(10):
        feed(pipe, dns_query(f"e{i}.dscb.akamaiedge.net"), T0 + i)
    assert "dns_tunnel" not in kinds(pipe)


def test_rogue_dhcp(pipe):
    def offer(server, mac):
        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=server, dst="255.255.255.255") / \
            UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr="192.168.1.50") / \
            DHCP(options=[("message-type", "offer"), ("server_id", server), "end"])
    feed(pipe, offer(GW, MAC_GW), T0)
    feed(pipe, offer("192.168.1.66", "02:00:00:00:00:66"), T0 + 2)
    alert = kinds(pipe)["rogue_dhcp"]
    assert alert.severity == "high" and alert.hosts == ["192.168.1.66"]


def test_helpers():
    assert registrable("a.b.example.co.uk") == ("a.b", "example.co.uk")
    assert registrable("www.github.com") == ("www", "github.com")
    assert entropy("aaaa") == 0 and entropy("abcd") == 2
