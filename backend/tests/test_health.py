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


# ------------------------------------------------------------ speed test
NQ_OUT = ('{"dl_throughput": 112096232, "ul_throughput": 149215408, "base_rtt": 10.9, '
          '"responsiveness": 248.2, "il_tls_handshake": [13, 15]}')
HOME, CAFE = "d4:01:c3:86:51:0b", "aa:bb:cc:dd:ee:01"


def test_speed_test_output_is_read_and_remembered_per_network(tmp_path):
    from app.speedtest import SpeedTest, parse
    r = parse(NQ_OUT)
    assert r["down"] == 112096232 and r["up"] == 149215408 and r["latency"] == 10.9
    assert parse("not json") is None and parse('{"dl_throughput": 0}') is None
    st = SpeedTest(tmp_path)
    st.record(HOME, r, when=1.0)
    st.record(HOME, {**r, "down": 55_000_000}, when=2.0)
    st.record(CAFE, {**r, "down": 8_000_000}, when=3.0)
    home = st.summary(HOME)
    assert home["last"]["down"] == 55_000_000            # latest result shown...
    assert home["limit"] == 112096232                     # ...best recent one is the limit
    assert st.limit_bps(CAFE) == 1_000_000                # 8 Mbit/s = 1 MB/s
    assert st.summary("11:22:33:44:55:66")["last"] is None   # a new place starts untested
    # It survives a restart, and only this user can read the file.
    again = SpeedTest(tmp_path)
    assert again.summary(HOME)["limit"] == 112096232
    assert (tmp_path / "speedtests.json").stat().st_mode & 0o077 == 0


def test_router_hardware_address_is_normalised(monkeypatch):
    from app import speedtest

    class Out:
        stdout = "? (10.128.123.1) at d4:1:c3:86:51:b on en0 ifscope [ethernet]\n"

    monkeypatch.setattr(speedtest.subprocess, "run", lambda *a, **k: Out())
    assert speedtest.router_mac("10.128.123.1") == HOME
    assert speedtest.router_mac("not an ip; rm -rf") is None


def test_heavy_use_is_measured_against_this_networks_speed(pipe):
    feed(pipe, tcp("17.57.146.20", SELF, 443, 50000, "A", smac=MAC_GW, dmac=MAC_SELF), T0 + 13)
    speed = {"limit": 16_000_000}                          # 16 Mbit/s = 2 MB/s
    for i in range(16):
        pipe.health.check(T0 + i, {"verdict": HEALTHY, "speed": speed}, 1_500_000)
    (a,) = alerts(pipe, "heavy_use")                       # 1.5 MB/s is 75% of this network
    assert "75% of your speed" in a.reason


def test_hiccups_only_alert_when_they_keep_happening(pipe):
    hiccups = {"title": "Your Wi-Fi has hiccups", "level": "warn", "stats": {"gw_spikes": 3}}
    t = run(pipe, hiccups, 60, T0)
    assert not alerts(pipe, "wifi_hiccups")
    run(pipe, hiccups, 100, t)
    (a,) = alerts(pipe, "wifi_hiccups")
    assert a.severity == "low" and "spiked 3×" in a.reason


def test_servers_are_named_by_the_name_asked_for_not_the_cdn_alias(pipe):
    from scapy.all import DNS, DNSQR, DNSRR, IP
    ans = (Ether(src=MAC_GW, dst=MAC_SELF) / IP(src="1.1.1.1", dst=SELF) / UDP(sport=53, dport=5300)
           / DNS(id=1, qr=1, qd=DNSQR(qname="media.licdn.com"),
                 an=[DNSRR(rrname="media.licdn.com", type="CNAME",
                           rdata="media.licdn.com.cdn.cloudflare.net"),
                     DNSRR(rrname="media.licdn.com.cdn.cloudflare.net", rdata="104.18.1.1")]))
    feed(pipe, ans, T0)
    assert pipe.hosts.names["104.18.1.1"] == "media.licdn.com"


def test_network_is_recognised_even_when_macos_hides_the_arp_table(monkeypatch):
    from app import speedtest
    monkeypatch.setattr(speedtest, "router_mac", lambda r: None)
    ra = "RouterAdvertisement : from fe80::d601:c3ff:fe86:510b, length 96"
    assert speedtest.network_id("en0", "10.128.123.1", ra) == HOME
    plain = ("subnet_mask (ip): 255.255.255.0\n"
             "domain_name_server (ip_mult): {192.168.1.1}\n")
    a = speedtest.network_id("en0", "192.168.1.1", plain)
    b = speedtest.network_id("en0", "192.168.1.1", plain.replace("192.168.1.1}", "9.9.9.9}"))
    assert a.startswith("net-") and a != b


def test_a_download_that_just_finished_still_counts_as_this_mac(pipe):
    # The Wi-Fi verdict covers the last minute; a speed test that ended 20 s ago caused it.
    for i in range(12):
        pipe.health.check(T0 + i, {"verdict": SLOW_WIFI}, 20_000, mac_peak=9_000_000)
    (a,) = alerts(pipe, "slow_wifi")
    assert a.detail["this_mac"] is True and "was moving up to" in a.detail["why"]


def test_wifi_verdict_blames_this_mac_when_it_was_busy():
    from app.wifi import diagnose
    samples = [{"t": float(i), "pinged": True, "gw": 300.0 if i % 10 == 0 else 8.0,
                "net": 10.0, "rssi": -55, "noise": -95} for i in range(30)]
    v = diagnose(samples, {"connected": True}, "10.0.0.1", mac_bps=9_000_000)
    assert v["title"] == "This Mac is filling the connection" and v["level"] == "bad"
    assert "Wi-Fi itself is fine" in v["detail"]
    # On a slow network (1 MB/s measured), 600 KB/s is already most of it.
    v = diagnose(samples, {"connected": True}, "10.0.0.1", mac_bps=600_000, load=0.6)
    assert v["title"] == "This Mac is filling the connection" and "60%" in v["detail"]
    v = diagnose(samples, {"connected": True}, "10.0.0.1", mac_bps=10_000)
    assert v["title"] == "Your Wi-Fi has hiccups" and "another device" in v["detail"]


def test_the_macs_own_byte_counters_are_read(monkeypatch):
    from app import wifi

    class Out:
        stdout = ("Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n"
                  "en0 1500 <Link#14> 02:00:00:00:00:00 10 0 4000 5 0 1000 0\n"
                  "en0 1500 10.0.0/24 10.0.0.2 10 - 4000 5 - 1000 -\n")

    monkeypatch.setattr(wifi.subprocess, "run", lambda *a, **k: Out())
    assert wifi.iface_bytes("en0") == (4000, 1000)
    assert wifi.iface_bytes("en0; ls") is None


def test_downloads_and_uploads_are_each_measured_against_their_own_speed():
    from app.wifi import WifiMonitor
    w = WifiMonitor(demo=False)
    w.rates.extend([(1.0, 14_000_000, 12_000_000), (6.0, 1_000, 1_000)])
    m = w.mac_rates(down=15_000_000, up=12_500_000)
    assert m["peak"] == 26_000_000                  # both directions together...
    assert round(m["peak_load"], 2) == 0.96         # ...but never "176% full"
    assert m["now_load"] < 0.01


def test_a_new_temporary_ipv6_address_of_this_mac_is_still_this_mac(pipe):
    # Learns this Mac's hardware address from its IPv4 traffic...
    feed(pipe, tcp(SELF, "17.57.146.20", 50000, 443, "A"), T0)
    # ...so a temporary IPv6 address macOS made up later is recognised as this Mac too.
    v6 = (Ether(src=MAC_SELF, dst=MAC_GW) / IPv6(src="2607:b940::71dc", dst="2620:149::f")
          / UDP(sport=5000, dport=443))
    feed(pipe, v6, T0 + 1)
    view = pipe.hosts.netview(T0 + 2)
    assert "2607:b940::71dc" in view["self"]["addrs"]
    assert view["counts"]["lan"] == 0
