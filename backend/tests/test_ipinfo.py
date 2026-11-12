"""'What is this address?': the plain-English text and the /api/ip endpoint (no network used)."""

import pytest

from app import ipinfo

GOOGLE = {"org": "Google LLC", "isp": "Google LLC", "asn": "AS15169", "domain": "google.com",
          "city": "Mountain View", "region": "California", "country": "United States",
          "cc": "US"}


@pytest.fixture(autouse=True)
def fresh_cache():
    ipinfo._cache.clear()
    yield
    ipinfo._cache.clear()


def test_this_mac_and_the_router_are_named_plainly():
    me = ipinfo.explain("192.168.1.23", {"kind": "self"}, None, None, "private")
    assert me["title"] == "This Mac" and "your Mac" in me["summary"]
    gw = ipinfo.explain("192.168.1.1", {"kind": "gateway"}, None, None, "private")
    assert gw["title"] == "Your router" and "connects your home network" in gw["summary"]


def test_a_home_device_uses_the_name_the_app_saw():
    d = ipinfo.explain("192.168.1.77", {"kind": "lan", "name": "Living-Room-TV",
                                        "mac": "02:00:00:00:00:77"}, None, None, "private")
    assert d["title"] == "Living-Room-TV"
    assert "home network" in d["summary"]
    labels = {f["label"]: f["value"] for f in d["facts"]}
    assert labels["Hardware address"] == "02:00:00:00:00:77"
    assert "private address" in labels["Address"]


def test_an_internet_server_names_its_owner_place_and_what_the_company_is():
    d = ipinfo.explain("142.250.80.14", {"kind": "internet", "name": "mail.google.com",
                                         "packets": 1200, "bytes_in": 3_400_000,
                                         "bytes_out": 90_000, "first": 1.0},
                       GOOGLE, "lax17s55-in-f14.1e100.net", "ok")
    assert d["title"] == "mail.google.com"
    assert "run by Google LLC" in d["summary"] and "Mountain View" in d["summary"]
    assert "Gmail" in d["summary"]                       # the plain-English note about Google
    labels = {f["label"]: f["value"] for f in d["facts"]}
    assert labels["Owner"] == "Google LLC" and labels["Network"] == "AS15169"
    assert "Address" not in labels and "Name seen" not in labels   # both already in the header
    assert labels["Reverse DNS"].endswith("1e100.net")
    assert labels["Traffic"].startswith("1,200 packets · 3.4 MB in")


def test_when_the_owner_cannot_be_found_it_says_so_instead_of_guessing():
    off = ipinfo.explain("93.184.215.14", {"kind": "internet", "name": ""}, None, None,
                         "unreachable")
    assert "couldn't find out who runs it" in off["summary"] and "no internet" in off["summary"]
    disabled = ipinfo.explain("93.184.215.14", {"kind": "internet"}, None, None, "disabled")
    assert "turned off" in disabled["summary"]


def test_big_networks_get_a_note_and_unknown_ones_do_not():
    assert "CDN" in ipinfo.service_note("Cloudflare, Inc.")
    assert "cloud hosting" in ipinfo.service_note("Amazon Technologies Inc.")
    assert ipinfo.service_note("Some Small ISP Ltd") == ""


def test_endpoint_answers_for_a_public_address_and_caches_it(authed, monkeypatch):
    calls = []

    def owner(ip, timeout=4.0):
        calls.append(ip)
        return GOOGLE

    monkeypatch.setattr(ipinfo, "fetch_owner", owner)
    monkeypatch.setattr(ipinfo, "reverse_name", lambda ip: "dns.google")
    r = authed.get("/api/ip/8.8.8.8")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and "Google LLC" in body["summary"]
    authed.get("/api/ip/8.8.8.8")
    assert calls == ["8.8.8.8"]                          # the second click came from the cache


def test_endpoint_never_goes_online_for_a_private_address(authed, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a private address must not be looked up online")

    monkeypatch.setattr(ipinfo, "fetch_owner", boom)
    monkeypatch.setattr(ipinfo, "reverse_name", boom)
    body = authed.get("/api/ip/192.168.1.50").json()
    assert body["status"] == "private" and "home network" in body["summary"]
    assert authed.get("/api/ip/fe80::1").json()["status"] == "private"


def test_endpoint_rejects_anything_that_is_not_an_ip(authed):
    for bad in ("not-an-ip", "999.1.1.1", "example.com"):
        assert authed.get(f"/api/ip/{bad}").status_code == 400


def test_the_lookup_can_be_turned_off(authed, runtime, monkeypatch):
    runtime.settings.ip_lookup = False

    def boom(*a, **k):
        raise AssertionError("lookups are switched off")

    monkeypatch.setattr(ipinfo, "fetch_owner", boom)
    body = authed.get("/api/ip/8.8.8.8").json()
    assert body["status"] == "disabled"


def test_a_failed_lookup_still_answers(authed, monkeypatch):
    def down(ip, timeout=4.0):
        raise OSError("offline")

    monkeypatch.setattr(ipinfo, "fetch_owner", down)
    monkeypatch.setattr(ipinfo, "reverse_name", lambda ip: None)
    body = authed.get("/api/ip/1.1.1.1").json()
    assert body["status"] == "unreachable" and "A server on the internet" in body["summary"]
