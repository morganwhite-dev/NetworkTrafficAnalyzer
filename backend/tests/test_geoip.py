import asyncio
import os
import stat

from app.geoip import GeoResolver, _valid, lookup_allowed


def test_only_public_unicast_is_looked_up():
    assert lookup_allowed("140.82.112.3")
    for addr in ("192.168.1.1", "10.0.0.1", "100.64.1.1", "224.0.0.251", "127.0.0.1",
                 "169.254.1.1", "fe80::1", "ff02::fb", "not-an-ip", "240.0.0.1"):
        assert not lookup_allowed(addr), addr


def test_validation_rejects_hostile_fields():
    assert _valid({"lat": 91, "lon": 0}) is None
    assert _valid({"lat": "x", "lon": 0}) is None
    assert _valid({"lat": 1, "lon": 2, "cc": "<script>"}) is None
    ok = _valid({"lat": 52.37, "lon": 4.89, "cc": "nl", "city": "A\x1b[31m" + "m" * 200})
    assert ok["cc"] == "NL" and "\x1b" not in ok["city"] and len(ok["city"]) <= 64


class FakeResponse:
    status_code = 200

    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class FakeClient:
    def __init__(self, data):
        self.data = data
        self.sent = None

    async def post(self, url, json):
        self.sent = json
        return FakeResponse(self.data)


def test_ip_api_batch_and_private_cache(tmp_path):
    geo = GeoResolver("ip-api", tmp_path / "missing.mmdb", tmp_path)
    assert geo.provider == "ip-api"
    assert geo.get("140.82.112.3") is None          # queued, not blocking
    assert geo.get("192.168.1.1") is None           # never queued
    assert list(geo.pending) == ["140.82.112.3"]
    client = FakeClient([
        {"query": "140.82.112.3", "status": "success", "lat": 37.7, "lon": -122.4,
         "countryCode": "US", "country": "United States", "city": "San Francisco",
         "org": "GitHub"},
        {"query": "6.6.6.6", "status": "success", "lat": 1, "lon": 1},   # not requested
    ])
    asyncio.run(geo._query(client, ["140.82.112.3"]))
    assert geo.get("140.82.112.3")["city"] == "San Francisco"
    assert "6.6.6.6" not in geo.cache
    geo._save_cache()
    mode = stat.S_IMODE(os.stat(tmp_path / "geo_cache.json").st_mode)
    assert mode == 0o600
    again = GeoResolver("ip-api", tmp_path / "missing.mmdb", tmp_path)
    assert again.get("140.82.112.3")["org"] == "GitHub"


def test_auto_without_db_is_off(tmp_path):
    geo = GeoResolver("auto", tmp_path / "missing.mmdb", tmp_path)
    assert geo.provider == "off" and geo.status["hint"]
