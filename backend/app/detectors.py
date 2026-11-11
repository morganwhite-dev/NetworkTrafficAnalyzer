"""Threat and anomaly detectors.

All detectors are driven by packet timestamps (``advance``), so a .pcap file
analysed in two seconds produces the same alerts as the live capture it came
from. Thresholds and the reasoning behind them are in docs/DETECTIONS.md.
"""

from __future__ import annotations

import math
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

from .hosts import SEVERITY_RANK, HostTracker, is_global
from .parser import ACK, RST, SYN, Facts
from .redact import Secret

FLAG_HOLD = 300          # a flagged host stays red for 5 minutes after its last alert
NOISY_UDP = {53, 67, 68, 123, 137, 138, 443, 1900, 5353, 5355, 3478, 3479, 3480, 3481, 4500}
STARTTLS_PORTS = {25, 587, 110, 143}


def fmt_rate(bps: float) -> str:
    for unit, div in (("GB/s", 1e9), ("MB/s", 1e6), ("KB/s", 1e3)):
        if bps >= div:
            return f"{bps / div:.3g} {unit}"
    return f"{bps:.0f} B/s"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def registrable(name: str) -> tuple[str, str]:
    """('sub.part', 'example.co.uk') using a small public-suffix approximation."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return "", name
    take = 2
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {
            "co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"}:
        take = 3
    return ".".join(labels[:-take]), ".".join(labels[-take:])


@dataclass
class Alert:
    id: int
    ts: float
    severity: str
    kind: str
    title: str
    reason: str
    hosts: list[str]
    detail: dict[str, Any] = field(default_factory=dict)
    secret: str | None = None
    packet_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "ts": self.ts, "severity": self.severity, "kind": self.kind,
                "title": self.title, "reason": self.reason, "hosts": self.hosts,
                "detail": self.detail, "packet_id": self.packet_id,
                "has_secret": self.secret is not None}


class AlertBook:
    def __init__(self, max_alerts: int = 500) -> None:
        self.items: deque[Alert] = deque(maxlen=max_alerts)
        self.by_id: OrderedDict[int, Alert] = OrderedDict()
        self.cooldown: dict[tuple, float] = {}
        self.max_alerts = max_alerts
        self._next = 1
        self.fresh: list[Alert] = []
        self.updated: list[Alert] = []
        self.by_key: dict[tuple, Alert] = {}
        self.refreshed: Alert | None = None

    def add(self, key: tuple, ts: float, severity: str, kind: str, title: str, reason: str,
            hosts: list[str], cooldown: float = 60, **extra: Any) -> Alert | None:
        last = self.cooldown.get(key)
        if last is not None and ts - last < cooldown:
            # Same incident still going: refresh its numbers instead of raising a new alert.
            existing = self.by_key.get(key)
            if existing is not None and existing.id in self.by_id:
                if (existing.reason, existing.detail) != (reason, extra.get("detail", {})):
                    existing.reason = reason
                    existing.detail = extra.get("detail", existing.detail)
                    if existing not in self.fresh and existing not in self.updated:
                        self.updated.append(existing)
                self.refreshed = existing
            return None
        self.cooldown[key] = ts
        if len(self.cooldown) > 20_000:
            for k in list(self.cooldown)[:5000]:
                del self.cooldown[k]
        alert = Alert(self._next, ts, severity, kind, title, reason, hosts, **extra)
        self._next += 1
        if len(self.items) == self.max_alerts:
            self.by_id.pop(self.items[0].id, None)
        self.items.append(alert)
        self.by_id[alert.id] = alert
        self.by_key[key] = alert
        if len(self.by_key) > 5000:
            for k in list(self.by_key)[:1000]:
                del self.by_key[k]
        self.fresh.append(alert)
        return alert

    def active(self, now: float, window: float = FLAG_HOLD) -> list[Alert]:
        live = [a for a in self.items if now - a.ts <= window and SEVERITY_RANK[a.severity] >= 2]
        live.sort(key=lambda a: (SEVERITY_RANK[a.severity], a.ts), reverse=True)
        seen, out = set(), []
        for a in live:
            key = (a.kind, a.hosts[0] if a.hosts else "")
            if key not in seen:
                seen.add(key)
                out.append(a)
        return out

    def clear(self) -> None:
        self.__init__(self.max_alerts)


class Engine:
    def __init__(self, hosts: HostTracker, book: AlertBook) -> None:
        self.hosts = hosts
        self.book = book
        self.reset_state()
        self.vpn: dict[str, Any] = {"active": False}

    def reset_state(self) -> None:
        self.last_sec: int | None = None
        self.sec_bytes: dict[int, int] = {}
        # port scan / sweep
        self.probes: OrderedDict[tuple, list] = OrderedDict()
        self.probe_log: dict[str, deque] = {}
        self.dirty_srcs: set[str] = set()
        self.scan_peak: dict[str, int] = {}
        self.arp_probe_log: dict[str, deque] = {}
        # spike baseline (per-second totals, spike seconds excluded)
        self.base: deque[int] = deque(maxlen=600)
        self.base_sum = 0
        self.base_sq = 0
        self.spike_run = 0
        self.baseline_mean: float | None = None
        # hog
        self.hog_streak: Counter[str] = Counter()
        # arp / ndp
        self.ip_mac: dict[str, str] = {}
        self.mac_changes: dict[str, deque] = {}
        # dns
        self.dns_subs: dict[str, deque] = {}
        self.dns_odd: dict[str, deque] = {}
        # dhcp / ra
        self.dhcp_servers: dict[str, float] = {}
        self.ra_routers: dict[str, float] = {}
        # cleartext
        self.tls_flows: OrderedDict[tuple, float] = OrderedDict()
        # vpn leak
        self.vpn_peers: dict[str, list] = {}

    # ------------------------------------------------------------------ utils
    def _raise(self, key: tuple, ts: float, severity: str, kind: str, title: str, reason: str,
               hosts: list[str], cooldown: float = 60, flag: list[str] | None = None,
               **extra: Any) -> Alert | None:
        self.book.refreshed = None
        alert = self.book.add(key, ts, severity, kind, title, reason, hosts, cooldown, **extra)
        target = alert or self.book.refreshed
        if target:
            for addr in (flag if flag is not None else hosts[:1]):
                self.hosts.flag(addr, target.severity, target.title, target.reason, target.id,
                                ts + FLAG_HOLD)
        return alert

    @staticmethod
    def _trim(dq: deque, now: float, window: float) -> None:
        while dq and now - dq[0][0] > window:
            dq.popleft()

    # --------------------------------------------------------------- packets
    def on_packet(self, f: Facts, pid: int, secrets: list[Secret]) -> None:
        self.sec_bytes[int(f.ts)] = self.sec_bytes.get(int(f.ts), 0) + f.length
        if f.l4 == "tcp":
            self._tcp(f)
        elif f.l4 == "udp":
            self._udp_probe(f)
        if f.quoted:
            self._icmp_unreachable(f)
        if f.proto == "ARP":
            self._arp(f)
        if f.nd_target:
            self._mac_binding(f.nd_target[0], f.nd_target[1], f.ts, "NDP")
        if f.dns_query and f.proto == "DNS":
            self._dns(f)
        if f.dhcp_server:
            self._rogue("dhcp", self.dhcp_servers, f.dhcp_server, f.ts, "Rogue DHCP server",
                        "DHCP servers answering")
        if f.ra_router:
            self._rogue("ra", self.ra_routers, f.ra_router, f.ts, "Rogue IPv6 router",
                        "routers advertising")
        if secrets or (f.l4 == "tcp" and f.dport == 23 and f.payload):
            self._cleartext(f, pid, secrets)
        if self.vpn.get("active"):
            self._vpn(f)
        self.advance(f.ts)

    def _tcp(self, f: Facts) -> None:
        flags = f.tcp_flags
        if flags & SYN and not flags & ACK and f.src and f.dst and not f.multicast_dst:
            key = (f.src, f.dst, "tcp", f.dport)
            if key not in self.probes:
                self.probes[key] = [f.ts, 0]
                self.probe_log.setdefault(f.src, deque()).append((f.ts, f.dst, "tcp", f.dport))
                self._cap_probes()
            self.dirty_srcs.add(f.src)
        elif flags & SYN and flags & ACK:
            p = self.probes.get((f.dst, f.src, "tcp", f.sport))
            if p:
                p[1] = 1
        elif flags & RST:
            p = self.probes.get((f.dst, f.src, "tcp", f.sport))
            if p and p[1] == 0:
                p[1] = 2
                self.dirty_srcs.add(f.dst)

    def _udp_probe(self, f: Facts) -> None:
        if f.multicast_dst or f.dport in NOISY_UDP or f.sport in NOISY_UDP or not f.src:
            return
        key = (f.src, f.dst, "udp", f.dport)
        if key not in self.probes:
            self.probes[key] = [f.ts, 0]
            self.probe_log.setdefault(f.src, deque()).append((f.ts, f.dst, "udp", f.dport))
            self._cap_probes()

    def _icmp_unreachable(self, f: Facts) -> None:
        l4, qsrc, qdst, qport = f.quoted  # type: ignore[misc]
        p = self.probes.get((qsrc, qdst, l4, qport))
        if p and p[1] == 0:
            p[1] = 2
            self.dirty_srcs.add(qsrc)

    def _cap_probes(self) -> None:
        while len(self.probes) > 50_000:
            self.probes.popitem(last=False)

    def _arp(self, f: Facts) -> None:
        if f.arp_op == 1 and f.arp_psrc and f.arp_pdst and f.arp_psrc != f.arp_pdst:
            log = self.arp_probe_log.setdefault(f.arp_psrc, deque())
            log.append((f.ts, f.arp_pdst))
            self._trim(log, f.ts, 10)
            targets = {t for _, t in log}
            if len(targets) >= 20:
                self._raise(("sweep-arp", f.arp_psrc), f.ts, "high", "host_sweep", "Host sweep",
                            f"ARP probes to {len(targets)} addresses in 10 s", [f.arp_psrc],
                            cooldown=120)
        if f.arp_psrc and f.arp_hwsrc and f.arp_psrc not in ("0.0.0.0",):  # noqa: S104
            if f.arp_op == 2 or f.arp_psrc == f.arp_pdst:
                self._mac_binding(f.arp_psrc, f.arp_hwsrc, f.ts, "ARP")
            elif f.arp_psrc not in self.ip_mac:
                self.ip_mac[f.arp_psrc] = f.arp_hwsrc

    def _mac_binding(self, addr: str, mac: str, ts: float, via: str) -> None:
        if not mac:
            return
        old = self.ip_mac.get(addr)
        self.ip_mac[addr] = mac
        if old is None or old == mac:
            return
        changes = self.mac_changes.setdefault(addr, deque())
        changes.append((ts, mac))
        self._trim(changes, ts, 60)
        is_gw = addr == self.hosts.gateway
        flipping = len(changes) >= 2
        owner = next((ip for ip, m in self.ip_mac.items() if m == mac and ip != addr), None)
        hosts = [addr] + ([owner] if owner else [])
        if is_gw or flipping:
            self._raise((f"{via}-spoof", addr), ts, "high", "arp_spoof", f"{via} spoofing",
                        f"{'Gateway ' if is_gw else ''}{addr} moved from {old} to {mac}",
                        hosts, cooldown=120, flag=hosts)
        else:
            self._raise((f"{via}-change", addr), ts, "low", "mac_change", "MAC address changed",
                        f"{addr} is now at {mac}", hosts, cooldown=600)

    def _dns(self, f: Facts) -> None:
        name, qtype = f.dns_query  # type: ignore[misc]
        if "." not in name or name.endswith((".local", ".arpa")):
            return
        sub, domain = registrable(name)
        if self.hosts.is_known_service(f.dst or "") or not sub:
            return
        subs = self.dns_subs.setdefault(domain, deque())
        subs.append((f.ts, sub))
        self._trim(subs, f.ts, 60)
        odd = self.dns_odd.setdefault(domain, deque())
        label_entropy = entropy(sub.replace(".", ""))
        if len(sub) >= 52 or (len(sub) >= 24 and label_entropy >= 4.2) or qtype in ("TXT", "NULL"):
            odd.append((f.ts, qtype))
        self._trim(odd, f.ts, 60)
        unique = len({s for _, s in subs})
        if unique >= 30 or len(odd) >= 20:
            why = (f"{unique} unique subdomains of {domain} in 60 s" if unique >= 30
                   else f"{len(odd)} long or TXT queries to {domain} in 60 s")
            self._raise(("dns", domain), f.ts, "medium", "dns_tunnel", "Possible DNS tunneling",
                        why, [f.src or ""], cooldown=300, detail={"domain": domain})

    def _rogue(self, kind: str, seen: dict[str, float], server: str, ts: float, title: str,
               what: str) -> None:
        seen[server] = ts
        for s in [s for s, t in seen.items() if ts - t > 600]:
            del seen[s]
        if len(seen) > 1:
            others = ", ".join(sorted(s for s in seen if s != server))
            self._raise((kind, server), ts, "high", f"rogue_{kind}", title,
                        f"{len(seen)} {what}: {server} and {others}", [server], cooldown=600)

    def _cleartext(self, f: Facts, pid: int, secrets: list[Secret]) -> None:
        flow = (f.src, f.dst, f.sport, f.dport)
        if f.dport in STARTTLS_PORTS and b"STARTTLS" in f.payload[:64].upper():
            self.tls_flows[flow] = f.ts
            while len(self.tls_flows) > 5000:
                self.tls_flows.popitem(last=False)
            return
        if flow in self.tls_flows:
            return
        server = f.dst or ""
        where = self.hosts.names.get(server) or f.http_host or server
        if f.dport == 23 and not secrets:
            self._raise(("telnet", f.src, server), f.ts, "low", "cleartext_session",
                        "Telnet session", f"Unencrypted Telnet to {where}", [server],
                        cooldown=600, packet_id=pid)
            return
        for s in secrets:
            value = f.payload[s.start:s.end].decode("utf-8", "replace")[:256]
            severity = "critical" if "password" in s.kind or "auth" in s.kind or \
                s.kind.endswith("credentials") else "high"
            self._raise(("creds", f.src, server, s.kind), f.ts, severity, "cleartext_credentials",
                        "Cleartext credentials", f"{s.kind} sent to {where}:{f.dport}",
                        [server, f.src or ""], cooldown=300, flag=[server],
                        secret=value, packet_id=pid,
                        detail={"field": s.field, "range": [f.payload_offset + s.start,
                                                            f.payload_offset + s.end]})

    def _vpn(self, f: Facts) -> None:
        if not f.src or f.src not in self.hosts.self_ips or not is_global(f.dst):
            return
        if f.dport in (53, 67, 68, 123, 5353):
            return
        peer = self.vpn_peers.setdefault(f.dst, [0, 0, f.ts])  # bytes, packets, first
        peer[0] += f.length
        peer[1] += 1
        tunnel = max(self.vpn_peers, key=lambda k: self.vpn_peers[k][0])
        if f.dst != tunnel and peer[1] >= 5:
            name = self.hosts.names.get(f.dst, f.dst)
            self._raise(("vpn", f.dst), f.ts, "high", "vpn_leak", "Possible VPN leak",
                        f"{name} reached outside the {self.vpn.get('tunnel', 'VPN')} tunnel",
                        [f.dst], cooldown=600)

    # ------------------------------------------------------------- per second
    def advance(self, now: float) -> None:
        sec = int(now)
        if self.last_sec is None:
            self.last_sec = sec - 1
        if sec <= self.last_sec:
            return
        start = max(self.last_sec + 1, sec - 120)
        for s in range(start, sec + 1):
            self._second(s)
        self.last_sec = sec
        self.hosts.expire(now)

    def _second(self, s: int) -> None:
        done = s - 1                      # the last complete second
        total = self.sec_bytes.pop(done, 0)
        for old in [k for k in self.sec_bytes if k < done]:
            del self.sec_bytes[old]
        self._scan_check(s)
        self._spike_check(done, total)
        self._hog_check(done)

    def _scan_check(self, now: float) -> None:
        for src in list(self.dirty_srcs):
            log = self.probe_log.get(src)
            if not log:
                self.dirty_srcs.discard(src)
                self.scan_peak.pop(src, None)
                continue
            self._trim(log, now, 10)
            failed, ports, lan_dsts = 0, set(), set()
            for ts, dst, l4, port in log:
                p = self.probes.get((src, dst, l4, port))
                if not p:
                    continue
                ports.add((dst, l4, port))
                if p[1] == 2 or (p[1] == 0 and now - ts > 2):
                    failed += 1
                    if self.hosts.kind_of(dst) in ("lan", "gateway", "self"):
                        lan_dsts.add(dst)
            if failed >= 20 and len(ports) >= 20:
                targets = Counter(d for d, _, _ in ports)
                target = targets.most_common(1)[0][0]
                if len(targets) <= 3 or targets[target] >= 20:
                    # Report the peak, not the shrinking tail as the window slides past.
                    peak = max(len(ports), self.scan_peak.get(src, 0))
                    self.scan_peak[src] = peak
                    self._raise(("scan", src), now, "high", "port_scan", "Port scan",
                                f"{peak} ports in 10 s", [src, target], cooldown=120,
                                flag=[src], detail={"target": target, "ports": peak})
            if len(lan_dsts) >= 20:
                self._raise(("sweep", src), now, "high", "host_sweep", "Host sweep",
                            f"{len(lan_dsts)} hosts probed in 10 s", [src], cooldown=120)
            if not log:
                self.dirty_srcs.discard(src)
                self.scan_peak.pop(src, None)

    def _spike_check(self, sec: int, total: int) -> None:
        n = len(self.base)
        mean = self.base_sum / n if n else 0.0
        var = max(0.0, self.base_sq / n - mean * mean) if n else 0.0
        std = math.sqrt(var)
        is_spike = n >= 30 and total > max(mean + 3 * std, 1_000_000)
        if is_spike:
            self.spike_run += 1
            if self.spike_run >= 5:
                top = self.hosts.top_talker(sec + 1)
                pct = (total / mean - 1) * 100 if mean else 0
                self._raise(("spike",), float(sec), "medium", "traffic_spike", "Traffic spike",
                            f"{fmt_rate(total)} · {pct:.0f}% above normal",
                            [top.ip] if top else [], cooldown=180, flag=[],
                            detail={"bps": total, "baseline": mean})
        else:
            self.spike_run = 0
            if len(self.base) == self.base.maxlen:
                old = self.base[0]
                self.base_sum -= old
                self.base_sq -= old * old
            self.base.append(total)
            self.base_sum += total
            self.base_sq += total * total
            self.baseline_mean = self.base_sum / len(self.base)

    def _hog_check(self, sec: int) -> None:
        now = sec + 1
        total10 = self.hosts.total_in_window(now - 1, 10)
        if total10 <= 0:
            self.hog_streak.clear()
            return
        top = self.hosts.top_talker(now - 1, 10)
        if top is None:
            return
        b10 = top.bytes_in_window(now - 1, 10)
        share, rate = b10 / total10, b10 / 10
        if share >= 0.6 and rate >= 2_000_000:
            self.hog_streak[top.ip] += 1
        else:
            self.hog_streak.pop(top.ip, None)
            return
        for ip in [k for k in self.hog_streak if k != top.ip]:
            del self.hog_streak[ip]
        if self.hog_streak[top.ip] >= 10:
            known = top.kind == "internet" and self.hosts.is_known_service(top.ip)
            total_rate = total10 / 10
            vs = ((total_rate / self.baseline_mean - 1) * 100
                  if self.baseline_mean and self.baseline_mean > 0 else None)
            self._raise(("hog", top.ip), float(sec), "info" if known else "high",
                        "bandwidth_hog", "Bandwidth hog",
                        f"{fmt_rate(rate)} · {share * 100:.0f}% of traffic", [top.ip],
                        cooldown=300, detail={"bps": rate, "share": share, "vs_normal": vs})


def now() -> float:
    return time.time()
