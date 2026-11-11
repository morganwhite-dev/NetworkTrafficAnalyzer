"""Geo-IP lookups: offline DB-IP City Lite by default, ip-api.com only if asked.

- Only public unicast addresses are ever looked up (no private, CGNAT,
  multicast, link-local or reserved ranges).
- ip-api's free tier is plain HTTP, so every field it returns is treated as
  hostile: types, lengths and coordinate ranges are checked before use.
- Results are cached on disk (mode 0600) so restarts don't re-query.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .textsafe import clean

IP_API_URL = "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,org,query"
IP_API_BATCH = 100
IP_API_INTERVAL = 4.5          # 15 requests/minute is the free limit; stay under it
CACHE_TTL = 7 * 86400
CACHE_MAX = 10_000


def lookup_allowed(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return bool(ip.is_global and not ip.is_multicast and not ip.is_reserved)


def _valid(entry: dict[str, Any]) -> dict[str, Any] | None:
    try:
        lat, lon = float(entry["lat"]), float(entry["lon"])
    except (KeyError, TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    cc = entry.get("cc") or ""
    if not (isinstance(cc, str) and (cc == "" or (len(cc) == 2 and cc.isalpha()))):
        return None
    return {
        "lat": round(lat, 4), "lon": round(lon, 4), "cc": cc.upper(),
        "country": clean(entry.get("country") or "", 64),
        "city": clean(entry.get("city") or "", 64),
        "org": clean(entry.get("org") or "", 96),
    }


class GeoResolver:
    def __init__(self, provider: str, db_path: Path, data_dir: Path) -> None:
        self.db = None
        self.provider = "off"
        if provider in ("auto", "dbip") and db_path.exists():
            try:
                import maxminddb
                self.db = maxminddb.open_database(str(db_path))
                self.provider = "dbip"
            except Exception:  # noqa: BLE001
                self.db = None
        if self.db is None and provider == "ip-api":
            self.provider = "ip-api"
        self.requested = provider
        self.data_dir = data_dir
        self.cache_path = data_dir / "geo_cache.json"
        self.cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.pending: OrderedDict[str, None] = OrderedDict()
        self.lock = threading.Lock()
        self.dirty = False
        self.last_error: str | None = None
        if self.provider == "ip-api":
            self._load_cache()

    @property
    def status(self) -> dict[str, Any]:
        hint = None
        if self.provider == "off":
            hint = ("No Geo-IP database found. Run scripts/download_geoip.sh for offline "
                    "lookups, or start with --geo ip-api to use the online service.")
        return {"provider": self.provider, "requested": self.requested, "hint": hint,
                "error": self.last_error, "cached": len(self.cache)}

    # ---------------------------------------------------------------- lookups
    def get(self, addr: str) -> dict[str, Any] | None:
        if self.provider == "off" or not lookup_allowed(addr):
            return None
        with self.lock:
            hit = self.cache.get(addr)
            if hit is not None:
                return hit.get("geo")
        if self.db is not None:
            geo = self._dbip(addr)
            self._store(addr, geo)
            return geo
        with self.lock:
            if addr not in self.pending and len(self.pending) < 5000:
                self.pending[addr] = None
        return None

    def _dbip(self, addr: str) -> dict[str, Any] | None:
        try:
            rec = self.db.get(addr)  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(rec, dict):
            return None
        loc = rec.get("location") or {}
        country = rec.get("country") or {}
        city = (rec.get("city") or {}).get("names", {}).get("en", "")
        return _valid({"lat": loc.get("latitude"), "lon": loc.get("longitude"),
                       "cc": country.get("iso_code") or "",
                       "country": (country.get("names") or {}).get("en", ""), "city": city})

    def _store(self, addr: str, geo: dict[str, Any] | None) -> None:
        with self.lock:
            self.cache[addr] = {"geo": geo, "t": time.time()}
            self.cache.move_to_end(addr)
            while len(self.cache) > CACHE_MAX:
                self.cache.popitem(last=False)
            self.dirty = True

    # ----------------------------------------------------------------- ip-api
    async def run(self) -> None:
        """Background task: batch pending lookups to ip-api (opt-in only)."""
        if self.provider != "ip-api":
            return
        import httpx
        async with httpx.AsyncClient(timeout=10, headers={"User-Agent": "nta/1.0"}) as client:
            while True:
                await asyncio.sleep(IP_API_INTERVAL)
                with self.lock:
                    batch = list(self.pending)[:IP_API_BATCH]
                    for a in batch:
                        self.pending.pop(a, None)
                if batch:
                    await self._query(client, batch)
                if self.dirty:
                    await asyncio.to_thread(self._save_cache)

    async def _query(self, client: Any, batch: list[str]) -> None:
        try:
            resp = await client.post(IP_API_URL, json=batch)
            if resp.status_code == 429:
                self.last_error = "ip-api rate limit hit; slowing down."
                await asyncio.sleep(60)
                return
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"ip-api request failed ({type(exc).__name__})."
            return
        if not isinstance(data, list):
            return
        self.last_error = None
        wanted = set(batch)
        for item in data[:IP_API_BATCH]:
            if not isinstance(item, dict):
                continue
            addr = item.get("query")
            if addr not in wanted:
                continue
            geo = None
            if item.get("status") == "success":
                geo = _valid({"lat": item.get("lat"), "lon": item.get("lon"),
                              "cc": item.get("countryCode") or "",
                              "country": item.get("country"), "city": item.get("city"),
                              "org": item.get("org")})
            self._store(addr, geo)

    # ------------------------------------------------------------------ cache
    def _load_cache(self) -> None:
        try:
            raw = json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        now = time.time()
        for addr, entry in list(raw.items())[-CACHE_MAX:]:
            if not (isinstance(entry, dict) and lookup_allowed(str(addr))):
                continue
            if now - float(entry.get("t", 0)) > CACHE_TTL:
                continue
            geo = entry.get("geo")
            self.cache[str(addr)] = {"geo": _valid(geo) if isinstance(geo, dict) else None,
                                     "t": float(entry.get("t", now))}

    def _save_cache(self) -> None:
        with self.lock:
            snapshot = dict(self.cache)
            self.dirty = False
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = self.cache_path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(snapshot, fh)
            os.replace(tmp, self.cache_path)
        except OSError as exc:
            self.last_error = f"Could not save the Geo-IP cache ({exc.strerror})."

    def clear_cache(self) -> None:
        with self.lock:
            self.cache.clear()
            self.pending.clear()
        try:
            self.cache_path.unlink(missing_ok=True)
        except OSError:
            pass
