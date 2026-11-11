"""Turn raw packets into table rows, detector facts and inspector trees.

Everything here runs on attacker-controlled bytes, so each public function
catches its own errors and falls back to a plain "Malformed" row instead of
taking the pipeline down.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Packet, Raw, conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    IPv6,
)

from .redact import HTTP_METHODS, mask_text
from .textsafe import clean
from .tlsinfo import client_hello_sni, is_tls_record

# Payload parsing in Scapy's HTTP layer can decompress bodies; never do that
# on untrusted traffic.
conf.contribs.setdefault("http", {})["auto_compression"] = False

DLT_EN10MB = 1

TCP_FLAG_NAMES = [("S", "SYN"), ("A", "ACK"), ("F", "FIN"), ("R", "RST"), ("P", "PSH"),
                  ("U", "URG"), ("E", "ECE"), ("C", "CWR")]
SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04

TCP_SERVICES = {21: "FTP", 23: "Telnet", 25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP",
                22: "SSH"}
CLEARTEXT_LOGIN_PORTS = {21, 23, 25, 587, 110, 143}
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC", 65: "HTTPS", 255: "ANY"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request",
              11: "Time exceeded"}
UNREACH_CODES = {0: "net", 1: "host", 2: "protocol", 3: "port", 13: "admin prohibited"}
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK",
              7: "Release", 8: "Inform"}

# Donut categories. Anything not listed is "Other".
CATEGORY = {"TLS": "TLS", "QUIC": "QUIC", "HTTP": "HTTP", "DNS": "DNS", "mDNS": "DNS",
            "ICMP": "ICMP", "ICMPv6": "ICMP", "ARP": "ARP", "TCP": "TCP", "SSH": "TCP",
            "FTP": "TCP", "Telnet": "TCP", "SMTP": "TCP", "POP3": "TCP", "IMAP": "TCP",
            "UDP": "UDP", "DHCP": "UDP", "NTP": "UDP", "SSDP": "UDP"}


@dataclass(slots=True)
class Facts:
    """Everything the detectors and host tracker need from one packet."""

    ts: float
    length: int
    proto: str = "Other"
    info: str = ""
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    l4: str | None = None
    tcp_flags: int = 0
    payload: bytes = b""
    payload_offset: int = 0
    src_mac: str | None = None
    dst_mac: str | None = None
    arp_op: int = 0
    arp_psrc: str | None = None
    arp_hwsrc: str | None = None
    arp_pdst: str | None = None
    dns_query: tuple[str, str] | None = None
    dns_response: bool = False
    dns_answers: list[tuple[str, str]] = field(default_factory=list)
    sni: str | None = None
    http_host: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    quoted: tuple[str, str, str, int] | None = None   # (l4, src, dst, dport) inside ICMP error
    dhcp_type: int | None = None
    dhcp_server: str | None = None
    dhcp_hostname: str | None = None
    ra_router: str | None = None
    nd_target: tuple[str, str] | None = None        # (ip, mac) from Neighbor Advertisement
    multicast_dst: bool = False

    @property
    def category(self) -> str:
        return CATEGORY.get(self.proto, "Other")


def link_type_of(pkt: Packet) -> int:
    return int(conf.l2types.layer2num.get(type(pkt), DLT_EN10MB))


def dissect(raw: bytes, linktype: int) -> Packet:
    cls = conf.l2types.num2layer.get(linktype)
    if cls is None:
        return Raw(raw)
    try:
        return cls(raw)
    except Exception:  # noqa: BLE001
        return Raw(raw)


def _flags_text(flags: int) -> str:
    names = [name for letter, name in TCP_FLAG_NAMES if flags & _FLAG_BITS[letter]]
    return ", ".join(names)


_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40,
              "C": 0x80}


def _is_multicast(addr: str | None) -> bool:
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_multicast or addr.endswith(".255") or addr == "255.255.255.255"


def _dns(f: Facts, dns: DNS) -> None:
    f.proto = "mDNS" if 5353 in (f.sport, f.dport) else "DNS"
    qname, qtype = "", ""
    try:
        if dns.qd:
            q = dns.qd[0]
            qname = clean(q.qname, 253).rstrip(".")
            qtype = DNS_QTYPES.get(int(q.qtype), str(q.qtype))
    except Exception:  # noqa: BLE001
        pass
    if dns.qr == 0:
        f.dns_query = (qname, qtype) if qname else None
        f.info = f"Query {qtype} {qname}".strip()
        return
    f.dns_response = True
    try:
        for rr in list(dns.an or [])[:32]:
            if int(rr.type) in (1, 28):
                f.dns_answers.append((clean(rr.rrname, 253).rstrip("."), str(rr.rdata)))
    except Exception:  # noqa: BLE001
        pass
    rcode = int(dns.rcode)
    if rcode == 3:
        f.info = f"Response {qtype} {qname} · no such name"
    elif f.dns_answers:
        extra = f" (+{len(f.dns_answers) - 1})" if len(f.dns_answers) > 1 else ""
        f.info = f"Response {qtype} {qname} → {f.dns_answers[0][1]}{extra}"
    else:
        f.info = f"Response {qtype} {qname}"


def _http(f: Facts, payload: bytes) -> bool:
    if payload.startswith(HTTP_METHODS):
        head = payload[:4096].split(b"\r\n\r\n", 1)[0].split(b"\r\n")
        parts = head[0].split(b" ")
        method = clean(parts[0], 10)
        path = clean(parts[1], 120) if len(parts) > 1 else "/"
        host = ""
        for line in head[1:]:
            if line.lower().startswith(b"host:"):
                host = clean(line[5:].strip(), 120)
                break
        f.http_host = host or None
        f.proto = "HTTP"
        f.info = mask_text(f"{method} {host}{path}")
        return True
    if payload.startswith(b"HTTP/1."):
        f.proto = "HTTP"
        f.info = clean(payload.split(b"\r\n", 1)[0], 80)
        return True
    return False


def _tcp(f: Facts, tcp: TCP) -> None:
    f.l4 = "tcp"
    f.sport, f.dport = int(tcp.sport), int(tcp.dport)
    f.tcp_flags = int(tcp.flags)
    payload = bytes(tcp.payload) if tcp.payload else b""
    f.payload = payload
    flag_text = _flags_text(f.tcp_flags)
    base = f"{f.sport} → {f.dport} [{flag_text}] seq={tcp.seq}"
    if f.tcp_flags & ACK:
        base += f" ack={tcp.ack}"
    base += f" win={tcp.window} len={len(payload)}"
    f.proto = "TCP"
    f.info = base
    if not payload:
        if 443 in (f.sport, f.dport):
            f.proto = "TCP"
        return
    if _http(f, payload):
        return
    if is_tls_record(payload):
        f.proto = "TLS"
        sni = client_hello_sni(payload)
        if sni:
            f.sni = sni
            f.info = f"Client Hello · {sni}"
        else:
            kind = {0x14: "Change Cipher Spec", 0x15: "Alert", 0x16: "Handshake",
                    0x17: "Application Data"}.get(payload[0], "Record")
            f.info = f"{kind} · {len(payload)} bytes"
        return
    service = TCP_SERVICES.get(f.dport) or TCP_SERVICES.get(f.sport)
    if service:
        f.proto = service
        first = clean(payload.split(b"\r\n", 1)[0], 80)
        if service in ("FTP", "POP3", "IMAP", "SMTP"):
            first = mask_text(first)
            upper = first.upper()
            if upper.startswith("PASS ") or " LOGIN " in upper or upper.startswith("AUTH PLAIN"):
                first = first.split(" ")[0] + " ••••"
        f.info = first if service != "SSH" else f.info


def _udp(f: Facts, udp: UDP, pkt: Packet) -> None:
    f.l4 = "udp"
    f.sport, f.dport = int(udp.sport), int(udp.dport)
    payload = bytes(udp.payload) if udp.payload else b""
    f.payload = payload
    f.proto = "UDP"
    f.info = f"{f.sport} → {f.dport} len={len(payload)}"
    if pkt.haslayer(DNS) and ({53, 5353} & {f.sport, f.dport}):
        _dns(f, pkt[DNS])
    elif pkt.haslayer(BOOTP):
        _dhcp(f, pkt)
    elif 443 in (f.sport, f.dport):
        f.proto = "QUIC"
        if payload:
            f.info = "QUIC Initial" if payload[0] & 0x80 else "QUIC short header"
    elif 123 in (f.sport, f.dport):
        f.proto = "NTP"
    elif 1900 in (f.sport, f.dport):
        f.proto = "SSDP"
        f.info = clean(payload.split(b"\r\n", 1)[0], 80)


def _dhcp(f: Facts, pkt: Packet) -> None:
    f.proto = "DHCP"
    bootp = pkt[BOOTP]
    msg_type = None
    hostname = None
    server_id = None
    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            if opt[0] == "message-type":
                msg_type = int(opt[1])
            elif opt[0] == "hostname":
                hostname = clean(opt[1], 64)
            elif opt[0] == "server_id":
                server_id = str(opt[1])
    f.dhcp_type = msg_type
    f.dhcp_hostname = hostname
    if msg_type in (2, 5):
        f.dhcp_server = server_id or f.src
    label = DHCP_TYPES.get(msg_type or 0, "Message")
    yiaddr = bootp.yiaddr if bootp.yiaddr and bootp.yiaddr != "0.0.0.0" else ""  # noqa: S104
    f.info = f"DHCP {label}" + (f" · {yiaddr}" if yiaddr else "") + \
        (f" · {hostname}" if hostname else "")


def _icmp(f: Facts, icmp: ICMP) -> None:
    f.l4 = "icmp"
    f.proto = "ICMP"
    f.icmp_type, f.icmp_code = int(icmp.type), int(icmp.code)
    name = ICMP_TYPES.get(f.icmp_type, f"Type {f.icmp_type}")
    if f.icmp_type in (0, 8):
        f.info = f"{name} id={icmp.id} seq={icmp.seq}"
    elif f.icmp_type == 3:
        f.info = f"{name} ({UNREACH_CODES.get(f.icmp_code, f.icmp_code)})"
        inner = icmp.payload
        if isinstance(inner, IP):
            l4 = inner.payload
            if isinstance(l4, (UDP, TCP)):
                f.quoted = ("udp" if isinstance(l4, UDP) else "tcp", inner.src, inner.dst,
                            int(l4.dport))
    else:
        f.info = name


def _icmp6(f: Facts, pkt: Packet) -> None:
    f.l4 = "icmp6"
    f.proto = "ICMPv6"
    if pkt.haslayer(ICMPv6ND_RA):
        f.ra_router = f.src
        f.info = "Router Advertisement"
    elif pkt.haslayer(ICMPv6ND_NS):
        f.info = f"Neighbor Solicitation · who has {pkt[ICMPv6ND_NS].tgt}"
    elif pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        mac = f.src_mac or ""
        try:
            from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr
            if pkt.haslayer(ICMPv6NDOptDstLLAddr):
                mac = pkt[ICMPv6NDOptDstLLAddr].lladdr
        except Exception:  # noqa: BLE001
            pass
        f.nd_target = (str(na.tgt), mac)
        f.info = f"Neighbor Advertisement · {na.tgt} is at {mac}"
    elif pkt.haslayer(ICMPv6EchoRequest):
        f.info = "Echo request"
    elif pkt.haslayer(ICMPv6EchoReply):
        f.info = "Echo reply"
    else:
        f.info = clean(pkt.payload.payload.name if pkt.payload else "ICMPv6", 60)


def facts_from(pkt: Packet, ts: float, length: int) -> Facts:
    f = Facts(ts=ts, length=length)
    try:
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            f.src_mac, f.dst_mac = str(eth.src), str(eth.dst)
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            f.proto = "ARP"
            f.arp_op = int(arp.op)
            f.arp_psrc, f.arp_hwsrc, f.arp_pdst = str(arp.psrc), str(arp.hwsrc), str(arp.pdst)
            f.src, f.dst = f.arp_psrc, f.arp_pdst
            f.info = (f"Who has {arp.pdst}? Tell {arp.psrc}" if f.arp_op == 1
                      else f"{arp.psrc} is at {arp.hwsrc}")
            return f
        if pkt.haslayer(IP):
            ip = pkt[IP]
            f.src, f.dst = str(ip.src), str(ip.dst)
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            f.src, f.dst = str(ip6.src), str(ip6.dst)
        else:
            f.proto = "Other"
            f.info = clean(pkt.summary(), 120)
            return f
        f.multicast_dst = _is_multicast(f.dst)
        if pkt.haslayer(TCP):
            _tcp(f, pkt[TCP])
            f.payload_offset = length - len(f.payload)
        elif pkt.haslayer(UDP):
            _udp(f, pkt[UDP], pkt)
            f.payload_offset = length - len(f.payload)
        elif pkt.haslayer(ICMP):
            _icmp(f, pkt[ICMP])
        elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
            _icmp6(f, pkt)
        else:
            f.proto = "IPv6" if pkt.haslayer(IPv6) else "IP"
            f.info = clean(pkt.summary(), 120)
    except Exception as exc:  # noqa: BLE001
        f.proto = "Malformed"
        f.info = clean(f"Could not decode: {type(exc).__name__}", 80)
    return f


def row(pid: int, f: Facts) -> dict[str, Any]:
    """The compact dict sent to the browser for the packet table."""
    return {
        "id": pid,
        "t": round(f.ts, 6),
        "src": f.src or f.src_mac or "",
        "dst": f.dst or f.dst_mac or "",
        "sport": f.sport,
        "dport": f.dport,
        "proto": f.proto,
        "l4": f.l4,
        "len": f.length,
        "info": f.info,
    }


def layer_tree(pkt: Packet, max_layers: int = 12, max_fields: int = 40) -> list[dict[str, Any]]:
    """Per-layer fields with byte ranges, for the inspector."""
    out: list[dict[str, Any]] = []
    try:
        total = len(bytes(pkt))
    except Exception:  # noqa: BLE001
        return out
    layer: Packet | None = pkt
    while layer is not None and len(out) < max_layers:
        try:
            whole = len(bytes(layer))
            payload_len = len(bytes(layer.payload)) if layer.payload else 0
            start = total - whole
            fields = []
            for fd in layer.fields_desc[:max_fields]:
                try:
                    value = layer.getfieldval(fd.name)
                    shown = fd.i2repr(layer, value)
                except Exception:  # noqa: BLE001
                    shown = "?"
                fields.append({"name": clean(fd.name, 40), "value": clean(shown, 160)})
            out.append({"name": clean(layer.name, 60), "start": start,
                        "end": start + whole - payload_len, "fields": fields})
        except Exception:  # noqa: BLE001
            break
        nxt = layer.payload
        if not nxt or isinstance(nxt, type(None)) or nxt.__class__.__name__ == "NoPayload":
            break
        layer = nxt
    return out
