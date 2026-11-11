"""Per-host traffic accounting for the Network view (Map and Flows tabs).

Every packet is charged to the *remote* side from this Mac's point of view,
so the totals add up to what actually crossed the interface. In replay and
file mode we don't know which machine captured the traffic, so "self" is
inferred from which private address talks to the internet the most.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any

from .parser import Facts

WINDOW = 60
RATE_WINDOW = 5
TOP_INTERNET = 8
TOP_LAN = 6
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Big, well-known services: a bandwidth hog here is usually just a download.
KNOWN_SERVICE = re.compile(
    r"(apple|icloud|mzstatic|aaplimg|cdn-apple|akamai|cloudfront|fastly|googlevideo|gvt1|"
    r"ytimg|youtube|nflxvideo|netflix|steam|windowsupdate|microsoft|msedge|zoom|spotify|scdn|"
    r"ttvnw|twitch|dropbox|backblaze|github|githubusercontent|amazonaws|googleusercontent)",
    re.IGNORECASE,
)
PHONE = re.compile(r"(iphone|ipad|android|pixel|galaxy|phone)", re.IGNORECASE)
TV = re.compile(r"(tv|roku|chromecast|firetv|fire-tv|bravia|webos|tizen|shield)", re.IGNORECASE)
COMPUTER = re.compile(r"(macbook|imac|mac-mini|laptop|desktop|-pc|windows)", re.IGNORECASE)


def _ip(addr: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not addr:
        return None
    try:
        return ipaddress.ip_address(addr)
    except ValueError:
        return None


def is_global(addr: str | None) -> bool:
    ip = _ip(addr)
    return bool(ip and ip.is_global and not ip.is_multicast)


def is_private_unicast(addr: str | None) -> bool:
    ip = _ip(addr)
    return bool(ip and ip.is_private and not ip.is_multicast and not ip.is_loopback
                and not ip.is_link_local and not ip.is_unspecified
                and not str(ip).endswith(".255"))


@dataclass(slots=True)
class Host:
    ip: str
    kind: str
    first: float
    last: float = 0.0
    packets: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    mac: str | None = None
    secs: dict[int, int] = field(default_factory=dict)
    severity: str | None = None
    title: str | None = None
    reason: str | None = None
    alert_id: int | None = None
    flagged_until: float = 0.0

    def add(self, ts: float, length: int, outbound: bool) -> None:
        self.packets += 1
        if outbound:
            self.bytes_out += length
        else:
            self.bytes_in += length
        sec = int(ts)
        self.secs[sec] = self.secs.get(sec, 0) + length
        if ts > self.last:
            self.last = ts
        if len(self.secs) > WINDOW + 10:
            cutoff = sec - WINDOW
            for s in [s for s in self.secs if s <= cutoff]:
                del self.secs[s]

    def bytes_in_window(self, now: float, seconds: int) -> int:
        end = int(now)
        start = end - seconds
        return sum(v for s, v in self.secs.items() if start < s <= end)


class HostTracker:
    def __init__(self, max_hosts: int = 10_000) -> None:
        self.max_hosts = max_hosts
        self.hosts: OrderedDict[str, Host] = OrderedDict()
        self.names: OrderedDict[str, str] = OrderedDict()
        self.mac_names: dict[str, str] = {}
        self.mac_of: dict[str, str] = {}
        self.self_ips: set[str] = set()
        self.gateway: str | None = None
        self.gateway_mac: str | None = None
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.auto = True
        self._votes: Counter[str] = Counter()
        self._gw_mac_votes: Counter[str] = Counter()
        self.geo_lookup = None  # set by the pipeline: ip -> dict | None

    # ---------- configuration ----------
    def configure(self, self_ips: set[str], networks: list[str], gateway: str | None) -> None:
        self.self_ips = set(self_ips)
        self.networks = [ipaddress.ip_network(n, strict=False) for n in networks]
        self.gateway = gateway
        self.auto = not self_ips

    def reset(self) -> None:
        keep = (self.self_ips, self.networks, self.gateway, self.auto, self.geo_lookup)
        self.__init__(self.max_hosts)
        self.self_ips, self.networks, self.gateway, self.auto, self.geo_lookup = keep
        if self.auto:
            self.self_ips, self.networks, self.gateway = set(), [], None

    @property
    def network_label(self) -> str:
        v4 = [n for n in self.networks if n.version == 4]
        return str(v4[0]) if v4 else (str(self.networks[0]) if self.networks else "")

    def kind_of(self, addr: str) -> str:
        if addr in self.self_ips:
            return "self"
        if addr == self.gateway:
            return "gateway"
        ip = _ip(addr)
        if ip is None or ip.is_multicast or ip.is_unspecified or ip.is_loopback:
            return "other"
        if any(ip in n for n in self.networks if n.version == ip.version):
            return "lan"
        if ip.is_link_local:
            return "lan"
        if is_global(addr):
            return "internet"
        if self.auto and ip.is_private:
            return "lan"
        return "other"

    # ---------- learning ----------
    def _learn(self, f: Facts) -> None:
        for name, addr in f.dns_answers:
            if name.endswith(".local"):          # mDNS: a LAN device announcing itself
                self._remember_name(addr, name[:-6], overwrite=True)
            else:
                self._remember_name(addr, name, overwrite=False)
        if f.sni and f.dst:
            self._remember_name(f.dst, f.sni, overwrite=True)
        if f.http_host and f.dst:
            self._remember_name(f.dst, f.http_host.split(":")[0], overwrite=False)
        if f.dhcp_hostname and f.src_mac:
            self.mac_names[f.src_mac] = f.dhcp_hostname
        if f.arp_psrc and f.arp_hwsrc and f.arp_psrc != "0.0.0.0":  # noqa: S104
            self.mac_of[f.arp_psrc] = f.arp_hwsrc

    def _remember_name(self, addr: str, name: str, overwrite: bool) -> bool:
        if not name or (not overwrite and addr in self.names):
            return False
        self.names[addr] = name
        self.names.move_to_end(addr)
        if len(self.names) > 20_000:
            self.names.popitem(last=False)
        return True

    def _infer_self(self, f: Facts) -> None:
        if f.src and f.dst:
            if is_private_unicast(f.src) and is_global(f.dst):
                self._votes[f.src] += 1
                if f.dst_mac:
                    self._gw_mac_votes[f.dst_mac] += 1
            elif is_private_unicast(f.dst) and is_global(f.src):
                self._votes[f.dst] += 1
        total = sum(self._votes.values())
        if total >= 40 and not self.self_ips:
            me, _ = self._votes.most_common(1)[0]
            self.self_ips = {me}
            ip = ipaddress.ip_address(me)
            self.networks = [ipaddress.ip_network(f"{me}/{24 if ip.version == 4 else 64}",
                                                  strict=False)]
            if self._gw_mac_votes:
                self.gateway_mac = self._gw_mac_votes.most_common(1)[0][0]
            # Move hosts we already saw into the right kind.
            for h in self.hosts.values():
                h.kind = self.kind_of(h.ip)

    def _resolve_gateway(self) -> None:
        if self.gateway or not self.self_ips:
            return
        if self.gateway_mac:
            for addr, mac in self.mac_of.items():
                if mac == self.gateway_mac and addr not in self.self_ips:
                    self.gateway = addr
                    break
        if not self.gateway and self.networks:
            net = self.networks[0]
            if net.version == 4:
                self.gateway = str(net.network_address + 1)
        if self.gateway and self.gateway in self.hosts:
            self.hosts[self.gateway].kind = "gateway"

    def _host(self, addr: str, ts: float) -> Host:
        h = self.hosts.get(addr)
        if h is None:
            h = Host(addr, self.kind_of(addr), first=ts)
            self.hosts[addr] = h
            if len(self.hosts) > self.max_hosts:
                for key, old in list(self.hosts.items()):
                    if old.kind not in ("self", "gateway") and not old.severity:
                        del self.hosts[key]
                        break
        else:
            self.hosts.move_to_end(addr)
        return h

    def observe(self, f: Facts) -> None:
        self._learn(f)
        if self.auto:
            if not self.self_ips:
                self._infer_self(f)
            self._resolve_gateway()
        src, dst = f.src, f.dst
        if not src or not dst or f.proto == "ARP":
            if f.proto == "ARP" and f.arp_psrc and self.kind_of(f.arp_psrc) in ("lan", "gateway"):
                h = self._host(f.arp_psrc, f.ts)
                h.mac = f.arp_hwsrc
                h.add(f.ts, f.length, outbound=False)
            return
        if src in self.self_ips:
            remote, outbound = dst, True
        elif dst in self.self_ips:
            remote, outbound = src, False
        elif self.kind_of(src) in ("lan", "gateway"):
            remote, outbound = src, False
        else:
            return
        kind = self.kind_of(remote)
        if kind in ("other", "self"):
            return
        h = self._host(remote, f.ts)
        h.kind = kind
        if not outbound and f.src_mac and kind in ("lan", "gateway"):
            h.mac = f.src_mac
        h.add(f.ts, f.length, outbound)

    # ---------- alerts ----------
    def flag(self, addr: str, severity: str, title: str, reason: str, alert_id: int,
             until: float) -> None:
        h = self.hosts.get(addr)
        if h is None:
            return
        if (h.severity is None or alert_id == h.alert_id
                or SEVERITY_RANK[severity] >= SEVERITY_RANK.get(h.severity, 0)):
            h.severity, h.title, h.reason, h.alert_id = severity, title, reason, alert_id
        h.flagged_until = max(h.flagged_until, until)

    def expire(self, now: float) -> None:
        for h in self.hosts.values():
            if h.severity and h.flagged_until < now:
                h.severity = h.title = h.reason = h.alert_id = None

    # ---------- views ----------
    def name_of(self, h: Host) -> str:
        if h.kind == "self":
            return "This Mac"
        if h.mac and h.mac in self.mac_names:
            return self.mac_names[h.mac]
        return self.names.get(h.ip, "")

    def device_of(self, h: Host) -> str:
        if h.kind == "self":
            return "laptop"
        if h.kind == "gateway":
            return "router"
        if h.kind == "internet":
            return "server"
        name = self.name_of(h)
        if PHONE.search(name):
            return "phone"
        if TV.search(name):
            return "tv"
        if COMPUTER.search(name):
            return "laptop"
        return "unknown"

    def is_known_service(self, addr: str) -> bool:
        return bool(KNOWN_SERVICE.search(self.names.get(addr, "")))

    def total_in_window(self, now: float, seconds: int) -> int:
        return sum(h.bytes_in_window(now, seconds) for h in self.hosts.values())

    def top_talker(self, now: float, seconds: int = RATE_WINDOW) -> Host | None:
        best, best_bytes = None, 0
        for h in self.hosts.values():
            b = h.bytes_in_window(now, seconds)
            if b > best_bytes:
                best, best_bytes = h, b
        return best

    def describe(self, h: Host, now: float, total60: int) -> dict[str, Any]:
        b60 = h.bytes_in_window(now, WINDOW)
        end = int(now)
        geo = self.geo_lookup(h.ip) if (self.geo_lookup and h.kind == "internet") else None
        return {
            "ip": h.ip,
            "name": self.name_of(h),
            "kind": h.kind,
            "device": self.device_of(h),
            "bps": h.bytes_in_window(now, RATE_WINDOW) / RATE_WINDOW,
            "share": (b60 / total60) if total60 else 0.0,
            "bytes60": b60,
            "packets": h.packets,
            "bytes_in": h.bytes_in,
            "bytes_out": h.bytes_out,
            "first": h.first,
            "last": h.last,
            "mac": h.mac,
            "cc": (geo or {}).get("cc"),
            "country": (geo or {}).get("country"),
            "city": (geo or {}).get("city"),
            "severity": h.severity,
            "title": h.title,
            "reason": h.reason,
            "alert_id": h.alert_id,
            "spark": [h.secs.get(s, 0) for s in range(end - WINDOW + 1, end + 1)],
        }

    def netview(self, now: float) -> dict[str, Any]:
        total60 = self.total_in_window(now, WINDOW)
        sev = lambda h: SEVERITY_RANK.get(h.severity or "", -1)  # noqa: E731
        hosts = list(self.hosts.values())
        lan = [h for h in hosts if h.kind == "lan"]
        internet = [h for h in hosts if h.kind == "internet"]
        lan.sort(key=lambda h: (sev(h) >= 2, h.bytes_in_window(now, WINDOW), h.last), reverse=True)
        internet.sort(key=lambda h: h.bytes_in_window(now, WINDOW), reverse=True)
        flagged_inet = [h for h in internet if sev(h) >= 2]
        top_inet = flagged_inet[:TOP_INTERNET]
        for h in internet:
            if len(top_inet) >= TOP_INTERNET:
                break
            if h not in top_inet and h.last >= now - 300:
                top_inet.append(h)
        top_inet.sort(key=lambda h: h.bytes_in_window(now, WINDOW), reverse=True)
        rest = [h for h in internet if h not in top_inet]
        rest_bytes = sum(h.bytes_in_window(now, WINDOW) for h in rest)
        gw = self.hosts.get(self.gateway) if self.gateway else None
        me = next(iter(sorted(self.self_ips)), None)
        flagged = [h for h in hosts if sev(h) >= 2]
        return {
            "now": now,
            "network": self.network_label,
            "self": {"ip": me, "name": "This Mac", "kind": "self", "device": "laptop",
                     "bps": self.total_in_window(now, RATE_WINDOW) / RATE_WINDOW,
                     "severity": None} if me else None,
            "gateway": self.describe(gw, now, total60) if gw else (
                {"ip": self.gateway, "name": "", "kind": "gateway", "device": "router", "bps": 0,
                 "share": 0, "severity": None, "spark": []} if self.gateway else None),
            "lan": [self.describe(h, now, total60) for h in lan[:TOP_LAN]],
            "lan_more": max(0, len(lan) - TOP_LAN),
            "internet": [self.describe(h, now, total60) for h in top_inet],
            "others": {"count": len(rest), "bps": sum(h.bytes_in_window(now, RATE_WINDOW)
                                                       for h in rest) / RATE_WINDOW,
                       "share": (rest_bytes / total60) if total60 else 0.0},
            "counts": {"hosts": len(lan) + len(internet) + (1 if gw else 0), "lan": len(lan),
                       "internet": len(internet), "flagged": len(flagged)},
            "total_bps": self.total_in_window(now, RATE_WINDOW) / RATE_WINDOW,
        }
