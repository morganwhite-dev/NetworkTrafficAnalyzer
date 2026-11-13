"""The packet pipeline: one worker thread owns all analysis state.

    sniffer / replay thread ──► bounded inbox ──► worker thread ──► outbox
                                                    │ parse, store, stats,
                                                    │ hosts, detectors, geo
    asyncio broadcaster ◄── take_outbox() ◄─────────┘

The inbox is bounded; when it's full new packets are dropped and counted
(shown in the UI) instead of growing memory without limit.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from scapy.all import Packet

from . import ipinfo
from .config import Settings
from .detectors import AlertBook, Engine
from .geoip import GeoResolver, short_org
from .health import HealthWatch
from .hosts import HostTracker
from .parser import (
    CLEARTEXT_LOGIN_PORTS,
    dissect,
    facts_from,
    header_end,
    layer_tree,
    link_type_of,
    row,
)
from .redact import HTTP_METHODS, MASK, find_secrets, mask_text
from .stats import Stats
from .store import PacketStore

OUTBOX_MAX = 5000


class Pipeline:
    def __init__(self, settings: Settings, geo: GeoResolver) -> None:
        self.settings = settings
        self.geo = geo
        self.lock = threading.RLock()
        self.store = PacketStore(settings.ring_bytes)
        self.stats = Stats()
        self.hosts = HostTracker(settings.max_hosts)
        self.hosts.geo_lookup = self._geo_cached
        self.hosts.owner_lookup = self._owner_of
        self.apps = None              # AppMap, set by the runtime (live mode only)
        self.hosts.app_lookup = self._app_of
        self.alerts = AlertBook(settings.max_alerts)
        self.engine = Engine(self.hosts, self.alerts)
        self.health = HealthWatch(self.engine)
        self.wifi = None              # WifiMonitor, set by the runtime
        self.inbox: deque = deque()
        self.dropped = 0
        self.kernel_recv = 0          # packets the kernel handed to the capture socket
        self.kernel_drop = 0          # packets the kernel discarded because we read too slowly
        self.kernel_drop_base = 0     # drops that happened before the last Clear
        self.out_rows: deque[dict[str, Any]] = deque(maxlen=OUTBOX_MAX)
        self.out_skipped = 0
        self.mode = "idle"            # idle | live | replay | file
        self.source = ""              # interface name or file name
        self.clock = 0.0
        self.generation = 0           # bumps on clear, so clients can resync
        self._wake = threading.Event()
        self._stop = False
        self._worker = threading.Thread(target=self._run, name="pipeline", daemon=True)
        self._worker.start()

    # ------------------------------------------------------------------ input
    def submit(self, item: Packet | bytes, ts: float, linktype: int, wirelen: int) -> None:
        """Called from capture threads. Never blocks."""
        if len(self.inbox) >= self.settings.queue_max:
            self.dropped += 1
            return
        self.inbox.append((item, ts, linktype, wirelen))
        self._wake.set()

    def _run(self) -> None:
        while not self._stop:
            self._wake.wait(0.05)
            self._wake.clear()
            while self.inbox:
                batch = []
                while self.inbox and len(batch) < 500:
                    batch.append(self.inbox.popleft())
                with self.lock:
                    for item in batch:
                        self._process(*item)

    def process_now(self, item: Packet | bytes, ts: float, linktype: int, wirelen: int) -> None:
        """Synchronous path used for uploaded files and tests."""
        with self.lock:
            self._process(item, ts, linktype, wirelen)

    def _process(self, item: Packet | bytes, ts: float, linktype: int, wirelen: int) -> None:
        if isinstance(item, (bytes, bytearray)):
            raw = bytes(item)
            pkt = dissect(raw, linktype)
        else:
            pkt = item
            raw = bytes(getattr(pkt, "original", None) or bytes(pkt))
            linktype = link_type_of(pkt)
        length = max(wirelen or 0, len(raw))
        f = facts_from(pkt, ts, length)
        secrets = []
        if f.payload and f.l4 == "tcp" and (f.dport in CLEARTEXT_LOGIN_PORTS
                                            or f.payload.startswith(HTTP_METHODS)):
            secrets = find_secrets(f.payload, f.dport)
        # Offsets must come from the bytes we hold, not the wire length: a snaplen-truncated
        # capture is shorter than `length`, which would shift every secret range.
        f.payload_offset = len(raw) - len(f.payload)
        r = row(0, f)
        ranges = [(f.payload_offset + s.start, f.payload_offset + s.end) for s in secrets]
        rec = self.store.add(ts, raw, linktype, r, ranges, header_end(pkt, len(raw)))
        self.stats.add(ts, length, f.category)
        self.hosts.observe(f)
        self.engine.on_packet(f, rec.id, secrets)
        if ts > self.clock:
            self.clock = ts
        for addr in (f.src, f.dst):
            if addr and self.hosts.kind_of(addr) == "internet":
                self.geo.get(addr)
        if len(self.out_rows) == OUTBOX_MAX:
            self.out_skipped += 1
        self.out_rows.append(r)

    # ----------------------------------------------------------------- output
    def _geo_cached(self, addr: str) -> dict[str, Any] | None:
        return self.geo.get(addr)

    def _owner_of(self, addr: str) -> str:
        # The offline table first; else what an earlier click on the address found out.
        return self.geo.owner(addr) or short_org(ipinfo.cached_owner(addr))

    def _app_of(self, addr: str) -> str:
        return self.apps.get(addr) if (self.apps is not None and self.mode == "live") else ""

    def now(self) -> float:
        return self.clock if self.mode == "file" else time.time()

    def tick(self) -> None:
        with self.lock:
            if self.mode in ("live", "replay"):
                self.engine.advance(time.time())

    def mac_peak(self, now: float | None = None) -> float:
        """This Mac's busiest 5 seconds in the last minute, in bytes/s. The Wi-Fi verdict
        covers the last minute, so "was this Mac busy?" has to look at the same minute."""
        with self.lock:
            vals = [v for _, v in self.stats.timeline(now or self.now(), 60)]
        if len(vals) < 5:
            return 0.0
        return max(sum(vals[i:i + 5]) / 5 for i in range(len(vals) - 4))

    def health_check(self, wifi: dict[str, Any]) -> None:
        """Once a second during a live capture: raise or end the slow-network alerts."""
        with self.lock:
            if self.mode != "live":
                return
            now = time.time()
            mac_bps = self.hosts.total_in_window(now, 10) / 10
            self.health.check(now, wifi, mac_bps, self.mac_peak(now))

    def take_outbox(self) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]]]:
        with self.lock:
            rows = list(self.out_rows)
            self.out_rows.clear()
            skipped, self.out_skipped = self.out_skipped, 0
            alerts = [a.to_dict() for a in self.alerts.fresh]
            self.alerts.fresh.clear()
            updated = [a.to_dict() for a in self.alerts.updated]
            self.alerts.updated.clear()
        return rows, skipped, alerts + [{**u, "update": True} for u in updated]

    def set_kernel_stats(self, received: int, dropped: int) -> None:
        """Called by the capture reader: the kernel's own count of what it saw and discarded."""
        self.kernel_recv, self.kernel_drop = received, dropped

    @property
    def kernel_dropped(self) -> int:
        return max(0, self.kernel_drop - self.kernel_drop_base)

    def stats_message(self) -> dict[str, Any]:
        with self.lock:
            now = self.now()
            pps, bps = self.stats.rate(now) if self.mode != "file" else (0.0, 0.0)
            return {"type": "stats", "pps": pps, "bps": bps, "t": int(now) - 1,
                    "packets": self.stats.total_packets, "bytes": self.stats.total_bytes,
                    "protocols": dict(self.stats.protocols), "dropped": self.dropped,
                    "kernel_dropped": self.kernel_dropped, "stored": len(self.store),
                    "evicted": self.store.evicted,
                    "spike": self.engine.spike_run > 0}

    def incidents(self, now: float, limit: int = 6) -> list[dict[str, Any]]:
        out = []
        for a in self.alerts.active(now)[:limit]:
            d = a.to_dict()
            host = self.hosts.hosts.get(a.hosts[0]) if a.hosts else None
            if host is not None:
                d["host"] = self.hosts.describe(host, now, self.hosts.total_in_window(now, 60))
            out.append(d)
        return out

    def netview_message(self) -> dict[str, Any]:
        with self.lock:
            now = self.now()
            view = self.hosts.netview(now)
            view["incidents"] = self.incidents(now)
            view["baseline"] = self.engine.baseline_mean
            view["timeline"] = self.stats.timeline(now, 60)
            view["type"] = "netview"
            return view

    def geo_message(self, limit: int = 400) -> dict[str, Any]:
        with self.lock:
            items = []
            for h in list(self.hosts.hosts.values())[-2000:]:
                if h.kind != "internet":
                    continue
                g = self.geo.get(h.ip)
                if not g:
                    continue
                items.append({"ip": h.ip, "name": self.hosts.name_of(h), "lat": g["lat"],
                              "lon": g["lon"], "cc": g["cc"], "country": g["country"],
                              "city": g["city"], "org": g.get("org", ""),
                              "packets": h.packets, "severity": h.severity})
            items.sort(key=lambda x: x["packets"], reverse=True)
            return {"type": "geo", "items": items[:limit], "provider": self.geo.provider}

    def snapshot(self, rows: int = 2000) -> dict[str, Any]:
        with self.lock:
            now = self.now()
            snap = {
                "type": "snapshot",
                "generation": self.generation,
                "mode": self.mode,
                "source": self.source,
                "packets": self.store.recent_rows(rows),
                "alerts": [a.to_dict() for a in list(self.alerts.items)[-200:]],
                "timeline": (self.stats.file_timeline() if self.mode == "file"
                             else self.stats.timeline(now, 60)),
            }
        snap["stats"] = self.stats_message()
        snap["netview"] = self.netview_message()
        snap["geo"] = self.geo_message()
        return snap

    def host_info(self, ip: str) -> dict[str, Any]:
        """What the app has seen of one address: kind, name, traffic, first seen."""
        with self.lock:
            now = self.now()
            group = self.hosts.group_of(ip)
            if not group:
                return {"kind": self.hosts.kind_of(ip), "name": self.hosts.names.get(ip, ""),
                        "owner": self.hosts.owner_of(ip), "app": self.hosts.app_of(ip)}
            # The clicked address first, then the device's other addresses.
            group.sort(key=lambda h: h.ip != ip)
            return self.hosts.describe_group(group, now, self.hosts.total_in_window(now, 60))

    def inspect(self, pid: int) -> dict[str, Any] | None:
        with self.lock:
            rec = self.store.get(pid)
            if rec is None:
                return None
            raw, linktype, ts, r, secrets = rec.raw, rec.linktype, rec.ts, rec.row, rec.secrets
        pkt = dissect(raw, linktype)
        shown = raw[:65536]
        # Keep detected secrets out of the decoded fields too (the hex view blurs them).
        # Scapy prints bytes as an escaped repr, so hide that spelling of each secret as well.
        hidden: set[str] = set()
        for start, end in secrets:
            if end - start >= 3:
                chunk = raw[start:end]
                hidden.add(chunk.decode("utf-8", "replace"))
                hidden.add(repr(chunk)[2:-1])

        def mask(val: str) -> str:
            val = mask_text(val)
            for sec in hidden:
                val = val.replace(sec, MASK)
            return val

        # Masked before the value is shortened, so a secret cut in half can't half-show.
        layers = layer_tree(pkt, mask=mask)
        return {"id": pid, "ts": ts, "linktype": linktype, "row": r, "caplen": len(raw),
                "hex": shown.hex(), "truncated": len(raw) > len(shown),
                "layers": layers, "secrets": [list(s) for s in secrets]}

    def reveal(self, alert_id: int) -> str | None:
        with self.lock:
            a = self.alerts.by_id.get(alert_id)
            return a.secret if a else None

    def clear(self) -> None:
        with self.lock:
            self.inbox.clear()
            self.store.clear()
            self.stats.clear()
            self.hosts.reset()
            self.alerts.clear()
            vpn = self.engine.vpn
            self.engine = Engine(self.hosts, self.alerts)
            self.engine.vpn = vpn
            self.health = HealthWatch(self.engine)
            self.out_rows.clear()
            self.dropped = 0
            self.kernel_drop_base = self.kernel_drop
            self.clock = 0.0
            self.generation += 1

    def close(self) -> None:
        self._stop = True
        self._wake.set()
