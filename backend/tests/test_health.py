"""Device names and merging, app lookups, and the slow-network alerts."""

import pytest
from scapy.all import UDP, Ether, IPv6

from app import apps
from app.config import Settings
from app.geoip import GeoResolver, short_org
from app.hosts import mac_is_private, maker_of
from app.pipeline import Pipeline
from helpers import GW, MAC_GW, MAC_SELF, SELF, tcp

T0 = 1_700_000_000.0
PHONE_MAC = "02:11:22:33:44:55"            # locally administered: a private address
APPLE_MAC = "f0:18:98:00:00:01"            # Apple's prefix


@pytest.fixture
def pipe(tmp_path):
    s = Settings()
    s.data_dir = tmp_path
    p = Pipeline(s, GeoResolver("off", s.geo_db, tmp_path))
    p.mode = "file"
    p.hosts.configure({SELF}, ["192.168.1.0/24"], GW)
    yield p
    p.close()


def feed(p, pkt, ts):
    p.process_now(bytes(pkt), ts, 1, 0)


# ---------------------------------------------------------------- names
def test_maker_comes_from_the_hardware_address_and_private_ones_are_spotted():
    assert maker_of(APPLE_MAC) == "Apple"
    assert mac_is_private(PHONE_MAC) and maker_of(PHONE_MAC) == ""
    assert not mac_is_private(APPLE_MAC)


def test_owner_names_are_shortened_to_what_people_call_the_company():
    assert short_org("Apple Inc.") == "Apple"
    assert short_org("Microsoft Corporation") == "Microsoft"
    assert short_org("Amazon.com, Inc.") == "Amazon"
    assert short_org("Google LLC") == "Google"


def test_one_device_with_several_addresses_is_one_tile(pipe):
    # The same phone talks to this Mac over IPv4 and over a link-local IPv6 address.
    feed(pipe, tcp("192.168.1.50", SELF, 5000, 7000, "A", smac=PHONE_MAC, dmac=MAC_SELF), T0)
    v6 = (Ether(src=PHONE_MAC, dst=MAC_SELF) / IPv6(src="fe80::1:2", dst="fe80::23")
          / UDP(sport=5353, dport=5353))
    feed(pipe, v6, T0 + 1)
    view = pipe.hosts.netview(T0 + 2)
    assert view["counts"]["lan"] == 1
    (phone,) = view["lan"]
    assert set(phone["addrs"]) == {"192.168.1.50", "fe80::1:2"}
    assert phone["ip"] == "192.168.1.50"           # IPv4 first
    assert phone["name"] == "Private device" and phone["device"] == "phone"


def test_the_routers_own_ipv6_address_is_not_a_second_device(pipe):
    feed(pipe, tcp(GW, SELF, 53, 7000, "A", smac=MAC_GW, dmac=MAC_SELF), T0)
    v6 = (Ether(src=MAC_GW, dst=MAC_SELF) / IPv6(src="fe80::1", dst="fe80::23")
          / UDP(sport=547, dport=546))
    feed(pipe, v6, T0 + 1)
    view = pipe.hosts.netview(T0 + 2)
    assert view["counts"]["lan"] == 0
    assert "fe80::1" in view["gateway"]["addrs"]


def test_a_server_without_a_name_is_labelled_by_its_owner_then_its_app(pipe):
    feed(pipe, tcp(SELF, "17.57.146.20", 50000, 443, "A"), T0)
    h = pipe.hosts.hosts["17.57.146.20"]
    assert pipe.hosts.label_of(h) == ""
    pipe.hosts.app_lookup = lambda ip: "Mail"
    assert pipe.hosts.label_of(h) == "Mail server"
    pipe.hosts.owner_lookup = lambda ip: "Apple"
    assert pipe.hosts.label_of(h) == "Apple"
    d = pipe.hosts.describe(h, T0 + 1, 1)
    assert d["app"] == "Mail" and d["owner"] == "Apple"


def test_rate_and_share_use_the_same_minute(pipe):
    feed(pipe, tcp(SELF, "17.57.146.20", 50000, 443, "A"), T0)
    d = pipe.hosts.netview(T0 + 30)["internet"][0]
    assert d["bps"] == 0                      # nothing in the last 5 s...
    assert d["avg_bps"] > 0 and d["share"] == 1.0   # ...but it is all of the last minute


# ------------------------------------------------------------------ apps
def test_lsof_output_becomes_apps_per_server():
    out = ("p1\ncGoogle Chrome Helper (Aperitif)\nf10\n"
           "n[2607:f8b0::5f]:51000->[2607:f8b0:4002::5f]:443\n"
           "p2\ncapsd\nf3\nn10.0.0.2:5000->17.57.146.20:5223\nf4\nn*:5353\n")
    got = apps.parse(out)
    assert got["2607:f8b0:4002::5f"].most_common(1)[0][0] == "Google Chrome"
    assert got["17.57.146.20"].most_common(1)[0][0] == "Apple push notifications"
    assert len(got) == 2


# ---------------------------------------------------------- slow network
SLOW_WIFI = {"title": "Your Wi-Fi is busy", "level": "bad", "detail": "busy", "tips": ["a"],
             "stats": {"gw_ms": 80.0, "net_ms": 95.0}}
HEALTHY = {"title": "Wi-Fi looks healthy", "level": "good", "stats": {}}


def run(pipe, verdict, seconds, start, mac_bps=0.0, link=None):
    for i in range(seconds):
        pipe.health.check(start + i, {"verdict": verdict, "link": link}, mac_bps)
    return start + seconds


def alerts(pipe, kind):
    return [a for a in pipe.alerts.items if a.kind == kind]


def test_slow_wifi_alerts_after_ten_seconds_and_blames_the_network_not_this_mac(pipe):
    t = run(pipe, SLOW_WIFI, 9, T0)
    assert not alerts(pipe, "slow_wifi")
    run(pipe, SLOW_WIFI, 2, t, mac_bps=40_000)
    (a,) = alerts(pipe, "slow_wifi")
    assert a.title == "Slow Wi-Fi: crowded" and a.severity == "medium"
    assert a.detail["this_mac"] is False and a.detail["why"].startswith("No.")
    assert "not this Mac" in a.reason


def test_slow_wifi_says_it_is_this_mac_when_this_mac_is_busy(pipe):
    feed(pipe, tcp("17.57.146.20", SELF, 443, 50000, "A", smac=MAC_GW, dmac=MAC_SELF), T0 + 9)
    pipe.hosts.app_lookup = lambda ip: "Steam"
    run(pipe, SLOW_WIFI, 12, T0, mac_bps=5_000_000)
    (a,) = alerts(pipe, "slow_wifi")
    assert a.detail["this_mac"] is True and "Steam" in a.detail["why"]


def test_the_slow_alert_ends_once_it_has_been_fine_for_a_while(pipe):
    t = run(pipe, SLOW_WIFI, 12, T0)
    t = run(pipe, HEALTHY, 19, t)
    (a,) = alerts(pipe, "slow_wifi")
    assert a.ended is None
    run(pipe, HEALTHY, 2, t)
    assert a.ended is not None
    # It comes back within ten minutes: the same alert is live again, not a new one.
    run(pipe, SLOW_WIFI, 12, t + 5)
    assert len(alerts(pipe, "slow_wifi")) == 1 and a.ended is None


def test_heavy_use_names_the_app_and_turns_amber_when_the_network_slows(pipe):
    feed(pipe, tcp("17.57.146.20", SELF, 443, 50000, "A", smac=MAC_GW, dmac=MAC_SELF), T0 + 13)
    pipe.hosts.app_lookup = lambda ip: "Steam"
    t = run(pipe, HEALTHY, 16, T0, mac_bps=4_000_000, link={"tx_rate": 400})
    (a,) = alerts(pipe, "heavy_use")
    assert a.severity == "low" and "Steam" in a.reason
    run(pipe, {**SLOW_WIFI, "level": "bad"}, 2, t, mac_bps=4_000_000)
    assert a.severity == "medium"
    run(pipe, HEALTHY, 11, t + 2, mac_bps=100_000)
    assert a.ended is not None and "peaked at" in a.reason


def test_slow_checks_only_run_live(pipe):
    pipe.mode = "replay"
    for _ in range(20):
        pipe.health_check({"verdict": SLOW_WIFI, "link": None})
    assert not alerts(pipe, "slow_wifi")
