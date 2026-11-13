"""Wi-Fi health check: signal strength plus router and internet response times.

The point is to answer "why is my Wi-Fi slow?" with one of three plain
answers: the signal is weak, the Wi-Fi itself is busy, or the internet past
the router is slow.

- Signal comes from Apple's CoreWLAN framework (no admin rights needed, and
  macOS hides the network name from apps without location access, which we
  don't ask for). Off macOS, or without PyObjC, only the pings run.
- Pings use the system /sbin/ping (no root needed). They run every 2 s while
  someone has the Wi-Fi tab open, and every 5 s during a live capture so a slow
  network can raise an alert. With neither, nothing is pinged.
"""

from __future__ import annotations

import os
import random
import re
import statistics
import subprocess
import sys
import threading
import time
from collections import deque
from typing import Any

from .speedtest import network_id

PING = "/sbin/ping" if sys.platform == "darwin" else "/bin/ping"
IPCONFIG = "/usr/sbin/ipconfig"
NETSTAT = "/usr/sbin/netstat"
INTERVAL = 2.0
BACKGROUND_INTERVAL = 5.0          # during a live capture with the Wi-Fi tab closed
HISTORY = 300                       # 10 minutes at one sample every 2 s
WINDOW = 60                         # the verdict looks at the last minute
ACTIVE_FOR = 15                     # pings keep running this long after the last keepalive
BANDS = {1: "2.4 GHz", 2: "5 GHz", 3: "6 GHz"}
WIDTHS = {1: "20 MHz", 2: "40 MHz", 3: "80 MHz", 4: "160 MHz", 5: "320 MHz"}
PHY = {1: "802.11a", 2: "802.11b", 3: "802.11g", 4: "Wi-Fi 4", 5: "Wi-Fi 5", 6: "Wi-Fi 6",
       7: "Wi-Fi 7"}
RTT = re.compile(r"time[=<]([\d.]+)\s*ms")


def signal_quality(rssi: float | None) -> str:
    if rssi is None:
        return "unknown"
    if rssi >= -60:
        return "strong"
    if rssi >= -67:
        return "good"
    if rssi >= -75:
        return "fair"
    return "weak"


def ping(host: str, timeout_ms: int = 1000) -> float | None:
    """One ICMP echo. Returns milliseconds, or None if it was lost."""
    if not host or not re.fullmatch(r"[0-9a-fA-F:.]{2,45}", host):
        return None
    wait = ["-W", str(timeout_ms)] if sys.platform == "darwin" else ["-W", "1"]
    try:
        out = subprocess.run([PING, "-c", "1", *wait, host], capture_output=True, text=True,
                             timeout=timeout_ms / 1000 + 1, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = RTT.search(out)
    return float(m.group(1)) if m else None


class CoreWlanReader:
    """Reads the current Wi-Fi link through CoreWLAN, if PyObjC is installed."""

    def __init__(self) -> None:
        self.iface = None
        try:
            import CoreWLAN  # type: ignore[import-not-found]
            self.iface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interface()
        except Exception:  # noqa: BLE001 - not macOS, or PyObjC not installed
            self.iface = None

    @property
    def available(self) -> bool:
        return self.iface is not None

    def read(self) -> dict[str, Any] | None:
        i = self.iface
        if i is None:
            return None
        try:
            if not i.powerOn():
                return {"connected": False, "reason": "Wi-Fi is turned off"}
            rssi = int(i.rssiValue())
            if rssi == 0:
                return {"connected": False, "reason": "Not connected to a Wi-Fi network"}
            ch = i.wlanChannel()
            return {
                "connected": True,
                "iface": str(i.interfaceName()),
                "rssi": rssi,
                "noise": int(i.noiseMeasurement()),
                "tx_rate": float(i.transmitRate()),
                "channel": int(ch.channelNumber()) if ch else None,
                "band": BANDS.get(int(ch.channelBand())) if ch else None,
                "width": WIDTHS.get(int(ch.channelWidth())) if ch else None,
                "phy": PHY.get(int(i.activePHYMode())),
            }
        except Exception:  # noqa: BLE001
            return None


def iface_bytes(iface: str) -> tuple[int, int] | None:
    """(bytes in, bytes out) on an interface, from macOS's own counters. Exact even when
    the packet capture can't keep up with a fast download."""
    if not re.fullmatch(r"[a-z0-9]{2,12}", iface or ""):
        return None
    try:
        out = subprocess.run([NETSTAT, "-ibn", "-I", iface], capture_output=True, text=True,
                             timeout=2, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 10 and cols[0] == iface and cols[2].startswith("<Link"):
            try:
                return int(cols[6]), int(cols[9])
            except ValueError:
                return None
    return None


def router_for(iface: str) -> str | None:
    if sys.platform != "darwin" or not re.fullmatch(r"[a-z0-9]{2,12}", iface or ""):
        return None
    try:
        out = subprocess.run([IPCONFIG, "getoption", iface, "router"], capture_output=True,
                             text=True, timeout=2, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out if re.fullmatch(r"[0-9.]{7,15}", out) else None


class DemoReader:
    """Synthetic readings for the README screenshots (NTA_WIFI_DEMO=1): a weak signal."""

    def __init__(self) -> None:
        self.rng = random.Random(7)

    available = True

    def read(self) -> dict[str, Any]:
        return {"connected": True, "iface": "en0", "rssi": self.rng.randint(-81, -74),
                "noise": -91, "tx_rate": float(self.rng.choice([58, 72, 86])), "channel": 6,
                "band": "2.4 GHz", "width": "20 MHz", "phy": "Wi-Fi 4"}

    def pings(self) -> tuple[float | None, float | None]:
        gw = None if self.rng.random() < 0.06 else self.rng.uniform(28, 95)
        net = None if gw is None or self.rng.random() < 0.03 else (gw + self.rng.uniform(14, 30))
        return gw, net


class WifiMonitor:
    def __init__(self, target: str = "1.1.1.1", demo: bool | None = None) -> None:
        self.demo = demo if demo is not None else os.environ.get("NTA_WIFI_DEMO") == "1"
        self.reader: Any = DemoReader() if self.demo else CoreWlanReader()
        self.target = target
        self.samples: deque[dict[str, Any]] = deque(maxlen=HISTORY)
        self.link: dict[str, Any] | None = None
        self.router: str | None = None
        self.active_until = 0.0
        self.background = lambda: False   # set by the runtime: live capture running?
        self.speed = None                 # SpeedTest, set by the runtime
        self.network: str | None = None   # this network's router hardware address
        self._bytes: tuple[float, int, int] | None = None
        self.rates: deque[tuple[float, float, float]] = deque(maxlen=60)  # (t, in/s, out/s)
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._router_checked = 0.0
        self.thread = threading.Thread(target=self._run, name="wifi", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    def keepalive(self) -> None:
        self.active_until = time.time() + ACTIVE_FOR

    @property
    def watched(self) -> bool:
        return time.time() < self.active_until

    @property
    def active(self) -> bool:
        return self.watched or bool(self.background())

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            self.sample_once()
            every = INTERVAL if (self.watched or self.demo) else BACKGROUND_INTERVAL
            self._stop.wait(max(0.2, every - (time.time() - started)))

    def sample_once(self) -> None:
        now = time.time()
        link = self.reader.read()
        if link and link.get("connected") and now - self._router_checked > 30 and not self.demo:
            self.router = router_for(link.get("iface", "en0"))
            self._router_checked = now
            self.network = network_id(link.get("iface", "en0"), self.router)
        if self.demo:
            self.router = "192.168.1.1"
        gw_ms = net_ms = None
        pinged = False
        if self.active and (self.demo or link is None or link.get("connected")):
            pinged = True
            if self.demo:
                gw_ms, net_ms = self.reader.pings()
            else:
                results: dict[str, float | None] = {}
                threads = [threading.Thread(target=lambda k=k, h=h: results.__setitem__(k, ping(h)))
                           for k, h in (("gw", self.router), ("net", self.target)) if h]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=2.5)
                gw_ms, net_ms = results.get("gw"), results.get("net")
        if not self.demo:
            self._count_bytes(now, (link or {}).get("iface") or "en0")
        sample = {"t": round(now, 2), "pinged": pinged, "gw": gw_ms, "net": net_ms}
        if link and link.get("connected"):
            sample.update(rssi=link["rssi"], noise=link["noise"], tx=link["tx_rate"])
        with self.lock:
            self.link = link
            self.samples.append(sample)

    def _count_bytes(self, now: float, iface: str) -> None:
        got = iface_bytes(iface)
        if got is None:
            return
        prev, self._bytes = self._bytes, (now, *got)
        if prev and now > prev[0] and got[0] >= prev[1] and got[1] >= prev[2]:
            dt = now - prev[0]
            with self.lock:
                self.rates.append((now, (got[0] - prev[1]) / dt, (got[1] - prev[2]) / dt))

    def mac_rates(self, down: float | None = None, up: float | None = None,
                  window: float = WINDOW) -> dict[str, Any]:
        """This Mac's traffic in the last minute: latest and busiest total (bytes/s), and,
        when the network has been speed-tested (`down`/`up` in bytes/s), how full the
        connection was: downloads against the download speed, uploads against the upload
        speed, whichever is fuller."""
        with self.lock:
            last = self.rates[-1][0] if self.rates else 0.0
            recent = [r for r in self.rates if last - r[0] <= window]
        if not recent:
            return {"now": 0.0, "peak": 0.0, "now_load": None, "peak_load": None}

        def load(r: tuple[float, float, float]) -> float | None:
            if not down:
                return None
            return max(r[1] / down, (r[2] / up) if up else 0.0)

        loads = [x for x in (load(r) for r in recent) if x is not None]
        return {"now": recent[-1][1] + recent[-1][2],
                "peak": max(r[1] + r[2] for r in recent),
                "now_load": load(recent[-1]), "peak_load": max(loads) if loads else None}

    # ------------------------------------------------------------------ view
    def message(self, mac_bps: float | None = None) -> dict[str, Any]:
        with self.lock:
            samples = list(self.samples)
            link = dict(self.link) if self.link else None
        speed = self.speed.summary(self.network) if self.speed else None
        down = ((speed or {}).get("limit") or 0) / 8 or None
        up = ((speed or {}).get("limit_up") or 0) / 8 or None
        mac = self.mac_rates(down, up)
        mac_bps = max(mac_bps or 0.0, mac["peak"]) or None
        return {
            "type": "wifi",
            "demo": self.demo,
            "signal_source": "CoreWLAN" if self.reader.available else None,
            "active": self.active,
            "router": self.router,
            "target": self.target,
            "link": link,
            "samples": samples[-150:],
            "verdict": diagnose(samples, link, self.router, mac_bps, mac["peak_load"]),
            "speed": speed,
            "mac": mac,
        }


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def diagnose(samples: list[dict[str, Any]], link: dict[str, Any] | None,
             router: str | None, mac_bps: float | None = None,
             load: float | None = None) -> dict[str, Any]:
    """`mac_bps`: this Mac's busiest moment in the last minute (bytes/s). `load`: how full
    that made the connection (0.6 = 60% of its measured speed), if it has been tested."""
    """Turn the last minute of readings into one plain-language answer."""
    if link is not None and not link.get("connected"):
        return {"level": "info", "title": link.get("reason", "Not on Wi-Fi"),
                "detail": "Connect to Wi-Fi and open this tab again to check it.", "tips": []}
    if not samples:
        return {"level": "info", "title": "Checking your Wi-Fi…", "detail": "", "tips": []}
    now = samples[-1]["t"]
    recent = [s for s in samples if now - s["t"] <= WINDOW]
    pinged = [s for s in recent if s.get("pinged")]
    rssi = _median([s["rssi"] for s in recent if s.get("rssi") is not None])
    noise = _median([s["noise"] for s in recent if s.get("noise") is not None])
    snr = (rssi - noise) if rssi is not None and noise is not None else None
    gw_ok = [s["gw"] for s in pinged if s.get("gw") is not None]
    net_ok = [s["net"] for s in pinged if s.get("net") is not None]
    gw_loss = (1 - len(gw_ok) / len(pinged)) if pinged and router else 0.0
    net_loss = (1 - len(net_ok) / len(pinged)) if pinged else 0.0
    gw_ms, net_ms = _median(gw_ok), _median(net_ok)
    gw_p90 = sorted(gw_ok)[int(len(gw_ok) * 0.9) - 1] if len(gw_ok) >= 10 else None
    spikes = sum(1 for v in gw_ok if v >= 50)
    quality = signal_quality(rssi)
    # Under 15 dB above the background noise is poor; 15-25 dB works fine for browsing.
    weak = quality == "weak" or (snr is not None and snr < 15)

    stats = {"rssi": rssi, "snr": snr, "quality": quality, "gw_ms": gw_ms, "gw_loss": gw_loss,
             "gw_p90": gw_p90, "gw_spikes": spikes,
             "net_ms": net_ms, "net_loss": net_loss, "seconds": len(pinged) * INTERVAL}
    if len(pinged) < 4:
        return {"level": "info", "title": "Measuring…",
                "detail": "Give it a few seconds to collect readings.", "tips": [],
                "stats": stats}

    gw_bad = gw_loss >= 0.05 or (gw_ms is not None and gw_ms >= 40)
    gw_warn = gw_ms is not None and gw_ms >= 15
    beyond = (net_ms - gw_ms) if net_ms is not None and gw_ms is not None else net_ms
    net_bad = net_loss >= 0.03 or (beyond is not None and beyond >= 120)
    net_warn = beyond is not None and beyond >= 60

    def ms(v: float | None) -> str:
        return "no answer" if v is None else f"{v:.0f} ms"

    sig = f"{rssi:.0f} dBm" if rssi is not None else "unknown"
    hog = ""
    busy_mac = (load >= 0.5) if load is not None else bool(mac_bps and mac_bps >= 2_000_000)
    if busy_mac:
        hog = (f" This Mac was moving up to {mac_bps / 1e6:.1f} MB/s in the last minute, which "
               "is enough to cause this on its own: a big download or upload makes the router "
               "queue everything else.")

    if busy_mac and (gw_bad or gw_warn or net_bad or net_warn or spikes >= 2):
        worst = max(gw_ok) if gw_ok else None
        of = f" ({min(load, 1.0):.0%} of this network's speed)" if load is not None else ""
        return {"level": "bad", "title": "This Mac is filling the connection", "stats": stats,
                "detail": (f"This Mac was moving up to {mac_bps / 1e6:.1f} MB/s in the last "
                           f"minute{of}, and the router slowed down to {ms(worst)} at the "
                           "same time. A big download or upload makes the router queue "
                           "everything else, so pages and calls on every device get slower. "
                           f"The Wi-Fi itself is fine ({quality} signal, {sig})."),
                "tips": ["Pause the download, upload, backup or stream and it clears up.",
                         "The Flows tab and the alert show which app and server it is.",
                         "If it's an update or backup, let it finish or run it overnight."]}
    if weak and (gw_bad or gw_warn):
        return {"level": "bad", "title": "Weak Wi-Fi signal", "stats": stats, "detail": (
            f"Your Mac hears the router at {sig}, which is weak, and the router takes "
            f"{ms(gw_ms)} to answer{f' and misses {gw_loss:.0%} of pings' if gw_loss else ''}. "
            "The slowness is most likely the signal between this Mac and the router." + hog),
            "tips": ["Move closer to the router, or out from behind walls and appliances.",
                     "Use the 5 GHz network if your router has one (faster, but shorter range).",
                     "If this spot is always weak, a mesh node or extender here will help."]}
    if gw_bad:
        return {"level": "bad", "title": "Your Wi-Fi is busy", "stats": stats, "detail": (
            f"The signal is fine ({sig}), but the router takes {ms(gw_ms)} to answer"
            f"{f' and misses {gw_loss:.0%} of pings' if gw_loss else ''}. That usually means "
            "the Wi-Fi is crowded: another device is using a lot, or neighbours' networks "
            "share your channel." + hog),
            "tips": ["Check your router's app or admin page for a device using a lot of data.",
                     "Restart the router, it clears up a surprising number of these.",
                     "Pick a less crowded channel in the router settings, or use 5 GHz."]}
    if net_bad:
        return {"level": "bad", "title": "Your internet connection is slow", "stats": stats,
                "detail": (f"Your Wi-Fi is fine: the router answers in {ms(gw_ms)}. But the "
                           f"internet takes {ms(net_ms)}"
                           f"{f' and drops {net_loss:.0%} of pings' if net_loss else ''}. "
                           "The problem is past your router, with the modem or your provider."),
                "tips": ["Restart the modem and router (unplug both for 30 seconds).",
                         "Run a speed test and compare it with the plan you pay for.",
                         "If it stays slow for a day, contact your provider."]}
    # Two or more big spikes a minute is what makes pages hang, even if the median is fine.
    hiccups = spikes >= 2
    if hiccups:
        worst = max(gw_ok)
        return {"level": "warn", "title": "Your Wi-Fi has hiccups", "stats": stats, "detail": (
            f"Most of the time the router answers in {ms(gw_ms)}, but in the last minute it "
            f"spiked to {worst:.0f} ms {spikes} times. Those spikes are what make pages hang and "
            "video calls stutter. The signal is "
            f"{quality} ({sig})" + (", so this Mac is the likely cause." + hog if busy_mac else
            ", so it's most likely another device grabbing the Wi-Fi in bursts, or "
            "interference from nearby networks.")),
            "tips": (["Pause the download, upload or stream, and see if the spikes stop.",
                      "The Flows tab shows which server it's going to."] if busy_mac else
                     ["Check your router's app or admin page for a device using a lot of data.",
                      "Watch the Flows tab during a spike to rule out this Mac.",
                      "Try a different Wi-Fi channel, or the 5 GHz or 6 GHz band if you're on "
                      "2.4."])}
    if weak:
        return {"level": "warn", "title": "Signal is on the weak side", "stats": stats,
                "detail": (f"Your Mac hears the router at {sig}. It's working for now (router "
                           f"answers in {ms(gw_ms)}), but speeds drop quickly at this level."),
                "tips": ["Moving a few metres closer to the router usually fixes it."]}
    if gw_warn or net_warn:
        return {"level": "warn", "title": "A little slow", "stats": stats, "detail": (
            f"Signal is {quality} ({sig}). The router answers in {ms(gw_ms)} and the internet "
            f"in {ms(net_ms)}, a bit slower than ideal but usable." + hog),
            "tips": ["Keep this tab open while it feels slow to see which number jumps."]}
    return {"level": "good", "title": "Wi-Fi looks healthy", "stats": stats, "detail": (
        f"{quality.capitalize()} signal ({sig}), the router answers in {ms(gw_ms)} and the "
        f"internet in {ms(net_ms)}." + (hog or " If things still feel slow, another device may "
        "be using the bandwidth: your router's device list will show which one.")),
        "tips": []}
