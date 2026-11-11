"""Packet builders shared by the tests (MACs are locally administered 02:…)."""

from __future__ import annotations

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw

MAC_SELF = "02:00:00:00:00:23"
MAC_GW = "02:00:00:00:00:01"
MAC_TV = "02:00:00:00:00:77"
SELF = "192.168.1.23"
GW = "192.168.1.1"


def eth(src=MAC_SELF, dst=MAC_GW):
    return Ether(src=src, dst=dst)


def tcp(src, dst, sport, dport, flags="S", payload=b"", smac=MAC_SELF, dmac=MAC_GW):
    p = eth(smac, dmac) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return p / Raw(payload) if payload else p


def udp(src, dst, sport, dport, payload=b"", smac=MAC_SELF, dmac=MAC_GW):
    return eth(smac, dmac) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)


def dns_query(name, src=SELF, dst="1.1.1.1", qtype="A"):
    return eth() / IP(src=src, dst=dst) / UDP(sport=53001, dport=53) / \
        DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype))


def dns_answer(name, ip, src="1.1.1.1", dst=SELF):
    return eth(MAC_GW, MAC_SELF) / IP(src=src, dst=dst) / UDP(sport=53, dport=53001) / \
        DNS(id=1, qr=1, qd=DNSQR(qname=name), an=[DNSRR(rrname=name, rdata=ip)])


def arp_reply(ip, mac):
    return Ether(src=mac, dst=MAC_SELF) / ARP(op=2, psrc=ip, hwsrc=mac, pdst=SELF,
                                              hwdst=MAC_SELF)


def arp_who_has(src_ip, src_mac, target):
    return Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=src_ip, hwsrc=src_mac,
                                                             pdst=target)


def icmp_port_unreachable(router, victim, quoted_dst, quoted_dport):
    inner = IP(src=victim, dst=quoted_dst) / UDP(sport=40000, dport=quoted_dport)
    return eth(MAC_GW, MAC_SELF) / IP(src=router, dst=victim) / ICMP(type=3, code=3) / inner


def client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = (b"\x00\x00" + (len(name) + 5).to_bytes(2, "big") + (len(name) + 3).to_bytes(2, "big")
               + b"\x00" + len(name).to_bytes(2, "big") + name)
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + len(sni_ext).to_bytes(2, "big") + sni_ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
