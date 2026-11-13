"""Slow-network alerts: "your Wi-Fi is slow", "your internet is slow", "heavy bandwidth use".

Runs once a second during a live capture, on top of the Wi-Fi tab's own readings (signal,
router and internet response times; see wifi.py) and this Mac's traffic. Each alert also
answers the question people actually have: is it this Mac, or something else?

- A slow verdict has to hold for HOLD seconds before it becomes an alert, and the alert is
  marked as ended once things have been fine for CLEAR seconds.
- "Heavy bandwidth use" fires when this Mac moves at least HEAVY_BPS for HEAVY_HOLD seconds.
  It names the app (from apps.py) and the server. It is amber if the network got slower
  at the same time (this Mac is filling the connection), otherwise just for information.
"""

from __future__ import annotations

from typing import Any

from .detectors import Engine, fmt_rate

HOLD = 10                 # seconds a slow verdict must last before alerting
CLEAR = 20                # seconds of normal before an alert is marked as ended
HEAVY_BPS = 3_000_000     # 3 MB/s (24 Mbit/s): enough to slow most home connections
HEAVY_HOLD = 15
HEAVY_CLEAR_BPS = 1_000_000
COOLDOWN = 600            # the same kind of slowness within 10 minutes re-opens one alert

# Wi-Fi verdict title -> (alert kind, severity, alert title)
SLOW = {
    "Weak Wi-Fi signal": ("slow_wifi", "medium", "Slow Wi-Fi: weak signal"),
    "Your Wi-Fi is busy": ("slow_wifi", "medium", "Slow Wi-Fi: crowded"),
    "Your internet connection is slow": ("slow_internet", "medium", "Slow internet"),
    "Your Wi-Fi has hiccups": ("wifi_hiccups", "low", "Wi-Fi hiccups"),
}


def _ms(v: float | None) -> str:
    return "no answer" if v is None else f"{v:.0f} ms"


class HealthWatch:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.slow_for = 0
        self.fine_for = 0
        self.slow_key: tuple | None = None
        self.heavy_for = 0
        self.light_for = 0
        self.heavy_peak = 0.0
        self.heavy_on = False

    def _top(self, now: float) -> tuple[str, str, str]:
        """(address, server label, app) of what this Mac is talking to the most."""
        hosts = self.engine.hosts
        top = hosts.top_talker(now, 10)
        if top is None:
            return "", "", ""
        return top.ip, hosts.label_of(top) or top.ip, hosts.app_of(top.ip)

    def blame(self, mac_bps: float, link: dict[str, Any] | None, now: float) -> tuple[bool, str]:
        """Is this Mac the reason it's slow? (yes/no, one plain sentence)."""
        ip, server, app = self._top(now)
        what = app or server
        capacity = (link or {}).get("tx_rate") or 0       # Wi-Fi link speed, Mbit/s
        share = (mac_bps * 8 / 1e6) / (capacity * 0.6) if capacity else None
        heavy = mac_bps >= 2_000_000 or (share is not None and share >= 0.5)
        if heavy:
            return True, (f"Yes, mostly. This Mac is moving {fmt_rate(mac_bps)}"
                          + (f", mostly {what}" if what else "")
                          + ". Pause that download or stream and see if it clears up.")
        return False, (f"No. This Mac is only using {fmt_rate(mac_bps)}, so the slowness is "
                       "coming from the network itself, or another device on it.")

    def check(self, now: float, wifi: dict[str, Any], mac_bps: float) -> None:
        verdict = wifi.get("verdict") or {}
        link = wifi.get("link")
        self._slow(now, verdict, link, mac_bps)
        self._heavy(now, verdict, link, mac_bps)

    # ------------------------------------------------------------- slow network
    def _slow(self, now: float, verdict: dict[str, Any], link: dict[str, Any] | None,
              mac_bps: float) -> None:
        rule = SLOW.get(verdict.get("title", ""))
        if rule is None:
            self.slow_for = 0
            self.fine_for += 1
            if self.slow_key and self.fine_for >= CLEAR:
                self.engine.book.end(self.slow_key, now)
                self.slow_key = None
            return
        self.fine_for = 0
        self.slow_for += 1
        if self.slow_for < HOLD:
            return
        kind, severity, title = rule
        st = verdict.get("stats") or {}
        is_mac, why = self.blame(mac_bps, link, now)
        speed = (f"router spiked {st.get('gw_spikes', 0)}× in a minute"
                 if kind == "wifi_hiccups" else
                 f"router {_ms(st.get('gw_ms'))} · internet {_ms(st.get('net_ms'))}")
        reason = f"{speed} · " + ("this Mac is busy" if is_mac else "not this Mac")
        ip, server, app = self._top(now)
        key = ("slow", kind)
        if self.slow_key and self.slow_key != key:
            self.engine.book.end(self.slow_key, now)
        self.slow_key = key
        self.engine._raise(  # noqa: SLF001 - same package
            key, now, severity, kind, title, reason, [ip] if (is_mac and ip) else [],
            cooldown=COOLDOWN, flag=[],
            detail={"gw_ms": st.get("gw_ms"), "net_ms": st.get("net_ms"),
                    "gw_loss": st.get("gw_loss"), "net_loss": st.get("net_loss"),
                    "rssi": st.get("rssi"), "mac_bps": mac_bps, "this_mac": is_mac,
                    "why": why, "summary": verdict.get("detail", ""),
                    "tips": verdict.get("tips", []), "app": app, "server": server})

    # ------------------------------------------------------------ heavy use
    def _heavy(self, now: float, verdict: dict[str, Any], link: dict[str, Any] | None,
               mac_bps: float) -> None:
        if mac_bps >= HEAVY_BPS:
            self.heavy_for += 1
            self.light_for = 0
            self.heavy_peak = max(self.heavy_peak, mac_bps)
        elif mac_bps < HEAVY_CLEAR_BPS:
            self.light_for += 1
            self.heavy_for = 0
        if self.heavy_on and self.light_for >= 10:
            self.engine.book.end(("heavy",), now,
                                 f"peaked at {fmt_rate(self.heavy_peak)} · finished")
            self.heavy_on = False
            self.heavy_peak = 0.0
        if self.heavy_for < HEAVY_HOLD:
            return
        ip, server, app = self._top(now)
        slower = verdict.get("level") in ("bad", "warn")
        capacity = (link or {}).get("tx_rate") or 0
        of_link = (mac_bps * 8 / 1e6) / capacity if capacity else None
        what = f"{app} ({server})" if app and server and app not in server else (app or server)
        reason = f"{fmt_rate(mac_bps)}" + (f" · mostly {what}" if what else "")
        why = (("Yes. The network got slower while this Mac was busy, so this Mac is "
                "filling the connection.") if slower else
               ("It could be. The network still answers quickly, so you probably won't notice, "
                "but other devices get less while this runs."))
        self.heavy_on = True
        self.engine._raise(  # noqa: SLF001 - same package
            ("heavy",), now, "medium" if slower else "low", "heavy_use",
            "Heavy bandwidth use", reason, [ip] if ip else [], cooldown=COOLDOWN, flag=[],
            detail={"bps": mac_bps, "peak": self.heavy_peak, "of_link": of_link,
                    "app": app, "server": server, "this_mac": True, "why": why})
