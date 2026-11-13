"""Speed test: how fast this network really is, remembered per network.

Runs macOS's own ``networkQuality`` tool (Apple's servers, no account, no admin
rights) only when you press "Test my speed". It moves a few hundred MB, so it
never runs by itself.

Results are kept per network, because a home, a campus and a café all have
different limits. A network is recognised by its router's hardware address
(macOS hides the Wi-Fi name from apps without location access, which this app
doesn't ask for; see network_id). The file lives in the app's data folder, mode 0600.

The "limit" for a network is the best download of its last few tests: a shared
network swings a lot, and the best recent result is the closest thing to what
the connection can do.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

NQ = "/usr/bin/networkQuality"
ARP = "/usr/sbin/arp"
IPCONFIG = "/usr/sbin/ipconfig"
KEEP = 5                   # tests remembered per network
MAX_NETWORKS = 50
TIMEOUT = 90


def router_mac(router: str | None) -> str | None:
    """The router's hardware address from the ARP table ("d4:1:c3:…" -> "d4:01:c3:…").
    macOS can hide it from apps without Local Network access, so callers fall back."""
    if not router or not re.fullmatch(r"[0-9.]{7,15}", router):
        return None
    try:
        out = subprocess.run([ARP, "-n", router], capture_output=True, text=True, timeout=3,
                             check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r" at ([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}) ", out)
    if not m:
        return None
    return ":".join(part.zfill(2) for part in m.group(1).lower().split(":"))


def eui64_mac(addr: str) -> str | None:
    """A link-local IPv6 address built from a hardware address (fe80::d601:c3ff:fe86:510b)
    gives that address back (d4:01:c3:86:51:0b)."""
    try:
        packed = ipaddress.IPv6Address(addr.split("%")[0]).packed
    except ValueError:
        return None
    iid = packed[8:]
    if iid[3:5] != b"\xff\xfe":
        return None
    mac = bytes([iid[0] ^ 0x02]) + iid[1:3] + iid[5:8]
    return ":".join(f"{b:02x}" for b in mac)


def network_id(iface: str, router: str | None, summary: str | None = None) -> str | None:
    """A stable name for the network you're on, to remember its speed under.

    1. the router's hardware address (ARP table), else
    2. the same address read from the router's IPv6 announcement, else
    3. a fingerprint of the router address, subnet and DNS servers.
    """
    mac = router_mac(router)
    if mac:
        return mac
    if summary is None:
        if not re.fullmatch(r"[a-z0-9]{2,12}", iface or ""):
            return None
        try:
            summary = subprocess.run([IPCONFIG, "getsummary", iface], capture_output=True,
                                     text=True, timeout=3, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return None
    m = re.search(r"RouterAdvertisement : from (fe80:[0-9a-fA-F:]+)", summary)
    mac = eui64_mac(m.group(1)) if m else None
    if mac:
        return mac
    if not router:
        return None
    mask = re.search(r"subnet_mask \(ip\): ([0-9.]+)", summary)
    dns = re.search(r"domain_name_server \(ip_mult\): \{([^}]*)\}", summary)
    raw = "|".join([router, mask.group(1) if mask else "", dns.group(1) if dns else ""])
    return "net-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def parse(output: str) -> dict[str, Any] | None:
    """networkQuality -c JSON -> {down, up (bits/s), latency (ms), responsiveness (RPM)}."""
    try:
        data = json.loads(output)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        down = float(data["dl_throughput"])
        up = float(data.get("ul_throughput") or 0)
    except (KeyError, TypeError, ValueError):
        return None
    if not 0 < down < 1e12:
        return None
    rtt = data.get("base_rtt")
    rpm = data.get("responsiveness")
    return {"down": down, "up": up,
            "latency": float(rtt) if isinstance(rtt, (int, float)) else None,
            "rpm": float(rpm) if isinstance(rpm, (int, float)) else None}


class SpeedTest:
    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "speedtests.json"
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.running = False
        self.error: str | None = None
        self.networks: dict[str, list[dict[str, Any]]] = {}
        self.available = sys.platform == "darwin" and Path(NQ).exists()
        self._load()

    # ------------------------------------------------------------- storage
    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for key, tests in list(raw.items())[:MAX_NETWORKS]:
            if not (isinstance(key, str) and re.fullmatch(r"[0-9a-f:]{17}|net-[0-9a-f]{12}", key)
                    and isinstance(tests, list)):
                continue
            good = [t for t in tests[-KEEP:] if isinstance(t, dict)
                    and isinstance(t.get("down"), (int, float))
                    and isinstance(t.get("t"), (int, float))]
            if good:
                self.networks[key] = good

    def _save(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(self.networks, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def record(self, key: str, result: dict[str, Any], when: float | None = None) -> None:
        with self.lock:
            tests = self.networks.setdefault(key, [])
            tests.append({**result, "t": when or time.time()})
            del tests[:-KEEP]
            while len(self.networks) > MAX_NETWORKS:
                oldest = min(self.networks, key=lambda k: self.networks[k][-1]["t"])
                del self.networks[oldest]
        self._save()

    # --------------------------------------------------------------- views
    def summary(self, key: str | None) -> dict[str, Any]:
        """What the Wi-Fi tab and the alerts need for the network you're on now."""
        with self.lock:
            tests = list(self.networks.get(key or "", []))
            count = len(self.networks)
        out: dict[str, Any] = {"available": self.available, "running": self.running,
                               "error": self.error, "network": key, "known_networks": count,
                               "last": None, "limit": None}
        if tests:
            out["last"] = tests[-1]
            out["limit"] = max(t["down"] for t in tests)        # bits/s
            out["limit_up"] = max(t.get("up") or 0 for t in tests) or None
            out["tests"] = len(tests)
        return out

    def limit_bps(self, key: str | None) -> float | None:
        """This network's download limit in bytes/s, if it has been tested."""
        s = self.summary(key)
        return s["limit"] / 8 if s["limit"] else None

    # ----------------------------------------------------------------- run
    def start(self, key: str | None, on_done=None) -> bool:
        """Run a test in the background. False if one is already running or it can't run."""
        if not self.available or not key:
            self.error = ("The speed test needs macOS's networkQuality tool."
                          if not self.available else "Not connected to a network.")
            return False
        with self.lock:
            if self.running:
                return False
            self.running, self.error = True, None
        threading.Thread(target=self._run, args=(key, on_done), name="speedtest",
                         daemon=True).start()
        return True

    def _run(self, key: str, on_done) -> None:
        try:
            out = subprocess.run([NQ, "-c"], capture_output=True, text=True, timeout=TIMEOUT,
                                 check=False).stdout
            result = parse(out)
            if result is None:
                self.error = "The speed test didn't finish. Check you're online and try again."
            else:
                self.record(key, result)
        except (OSError, subprocess.SubprocessError):
            self.error = "The speed test didn't finish. Check you're online and try again."
        finally:
            self.running = False
            if on_done:
                on_done()
