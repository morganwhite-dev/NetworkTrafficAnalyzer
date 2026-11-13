"""Which app on this Mac is talking to which server.

Every few seconds during a live capture this runs ``lsof -nP -i`` (no admin rights
needed; it lists the network connections of your own apps) and remembers, for each
remote address, the app that had a connection open to it. That turns
"2620:149:1360:101::12" into "Mail" and lets a slow-network alert say which app is
using the bandwidth.

- Only runs while a live capture is running. Never in demo or file mode, where the
  traffic isn't this Mac's right now.
- Nothing leaves the Mac: it reads the local connection table and nothing else.
- System background services get plain names ("Apple push notifications", "iCloud").
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import threading
import time
from collections import Counter

LSOF = "/usr/sbin/lsof"
INTERVAL = 3.0
KEEP = 600            # remember an address's app for 10 minutes after its last connection

# macOS background services, in plain words.
SYSTEM_APPS = {
    "com.apple.WebKit.Networking": "Safari or a web view",
    "com.apple.Safari.SafeBrowsing.Service": "Safari",
    "apsd": "Apple push notifications",
    "nsurlsessiond": "macOS background downloads",
    "cloudd": "iCloud",
    "bird": "iCloud Drive",
    "fileproviderd": "iCloud Drive",
    "softwareupdated": "Software Update",
    "mobileassetd": "macOS updates",
    "identityservicesd": "Messages and FaceTime",
    "imagent": "Messages",
    "rapportd": "AirDrop and Handoff",
    "sharingd": "AirDrop and Handoff",
    "mDNSResponder": "macOS name lookups",
    "trustd": "macOS certificate checks",
    "ocspd": "macOS certificate checks",
    "parsecd": "Spotlight suggestions",
    "assistantd": "Siri",
    "akd": "Apple ID",
    "accountsd": "Internet accounts",
    "photoanalysisd": "Photos",
    "cloudphotod": "iCloud Photos",
    "remindd": "Reminders",
    "CalendarAgent": "Calendar",
    "ControlCenter": "AirPlay",
    "replicatord": "Widgets",
    "Code": "VS Code",
    "claude": "Claude Code",
    "Python": "Python",
}

HELPER = re.compile(r"\s+(Helper|Networking|Web Content|Renderer|GPU)\b.*$|\s+\(.*\)$")


def friendly(command: str) -> str:
    """A process name in words a person recognises: "Google Chrome Helper (Aperitif)" ->
    "Google Chrome"."""
    name = command.strip()
    if name in SYSTEM_APPS:
        return SYSTEM_APPS[name]
    name = HELPER.sub("", name).strip()
    name = name.removesuffix(".app")
    return SYSTEM_APPS.get(name, name)[:32]


def remote_of(name: str) -> str | None:
    """The remote address in an lsof connection name: "a:1->[b]:443" -> "b"."""
    if "->" not in name:
        return None
    far = name.split("->", 1)[1].split(" ", 1)[0]
    host = far[1:far.index("]")] if far.startswith("[") else far.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(host.split("%")[0]))
    except ValueError:
        return None


def parse(output: str) -> dict[str, Counter[str]]:
    """lsof -F pcn output -> {remote address: Counter(app -> connections)}."""
    out: dict[str, Counter[str]] = {}
    app = ""
    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "c":
            app = friendly(value)
        elif tag == "n" and app:
            addr = remote_of(value)
            if addr:
                out.setdefault(addr, Counter())[app] += 1
    return out


class AppMap:
    def __init__(self) -> None:
        self.by_addr: dict[str, tuple[str, float]] = {}
        self.lock = threading.Lock()
        self.enabled = sys.platform == "darwin"
        self.active = lambda: False        # set by the runtime: is a live capture running?
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="apps", daemon=True)

    def start(self) -> None:
        if self.enabled:
            self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    def get(self, addr: str) -> str:
        with self.lock:
            hit = self.by_addr.get(addr)
        return hit[0] if hit else ""

    def clear(self) -> None:
        with self.lock:
            self.by_addr.clear()

    def _run(self) -> None:
        while not self._stop.is_set():
            if self.active():
                self.scan_once()
            self._stop.wait(INTERVAL)

    def scan_once(self) -> None:
        try:
            out = subprocess.run([LSOF, "-nP", "-i", "-F", "pcn", "+c", "0"],
                                 capture_output=True, text=True, timeout=8,
                                 check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return
        now = time.time()
        seen = parse(out)
        with self.lock:
            for addr, apps in seen.items():
                self.by_addr[addr] = (apps.most_common(1)[0][0], now)
            for addr in [a for a, (_, t) in self.by_addr.items() if now - t > KEEP]:
                del self.by_addr[addr]
            while len(self.by_addr) > 20_000:
                self.by_addr.pop(next(iter(self.by_addr)))
