from app.wifi import WifiMonitor, diagnose, ping, signal_quality

LINK = {"connected": True, "iface": "en0", "rssi": -55, "noise": -92, "tx_rate": 400.0}


def samples(rssi, gw, net, n=20, loss_every=0):
    out = []
    for i in range(n):
        lost = loss_every and i % loss_every == 0
        out.append({"t": 1000.0 + i * 2, "pinged": True, "rssi": rssi, "noise": -92,
                    "gw": None if lost else gw, "net": None if lost else net})
    return out


def test_signal_quality_bands():
    assert signal_quality(-50) == "strong"
    assert signal_quality(-65) == "good"
    assert signal_quality(-72) == "fair"
    assert signal_quality(-80) == "weak"
    assert signal_quality(None) == "unknown"


def test_weak_signal_is_blamed_when_the_router_is_slow():
    v = diagnose(samples(-79, 60, 80), LINK, "192.168.1.1")
    assert v["level"] == "bad" and v["title"] == "Weak Wi-Fi signal"
    assert "-79 dBm" in v["detail"] and v["tips"]


def test_busy_wifi_with_a_good_signal():
    v = diagnose(samples(-52, 70, 90, loss_every=10), LINK, "192.168.1.1")
    assert v["title"] == "Your Wi-Fi is busy"
    assert "misses 10% of pings" in v["detail"]


def test_slow_internet_past_the_router():
    v = diagnose(samples(-52, 3, 190), LINK, "192.168.1.1")
    assert v["title"] == "Your internet connection is slow"
    assert "router answers in 3 ms" in v["detail"]


def test_healthy_and_mentions_a_busy_mac():
    v = diagnose(samples(-50, 3, 20), LINK, "192.168.1.1")
    assert v["level"] == "good"
    v2 = diagnose(samples(-50, 3, 20), LINK, "192.168.1.1", mac_bps=6_400_000)
    assert "6.4 MB/s" in v2["detail"]


def test_needs_a_few_readings_and_handles_no_wifi():
    assert diagnose(samples(-50, 3, 20, n=2), LINK, "x")["title"] == "Measuring…"
    off = diagnose([], {"connected": False, "reason": "Wi-Fi is turned off"}, None)
    assert off["title"] == "Wi-Fi is turned off"


def test_ping_rejects_odd_hosts():
    assert ping("1.1.1.1; rm -rf /") is None
    assert ping("") is None


def test_demo_monitor_only_pings_while_active():
    m = WifiMonitor(demo=True)
    m.sample_once()
    assert m.samples[-1]["pinged"] is False
    m.keepalive()
    for _ in range(12):
        m.sample_once()
    msg = m.message()
    assert msg["demo"] and msg["link"]["band"] == "2.4 GHz"
    assert msg["samples"][-1]["pinged"] is True
    assert msg["verdict"]["title"] in ("Weak Wi-Fi signal", "Your Wi-Fi is busy")


def test_spiky_router_is_called_out_even_when_the_median_is_fine():
    s = samples(-55, 5, 12, n=30)
    for i in (3, 11, 19, 27):
        s[i]["gw"], s[i]["net"] = 85, 92
    v = diagnose(s, LINK, "192.168.1.1")
    assert v["title"] == "Your Wi-Fi has hiccups"
    assert "spiked to 85 ms 4 times" in v["detail"]
