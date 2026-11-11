"""Build samples/demo.pcap: 90 seconds of synthetic home-network traffic.

Everything here is made up for demos and screenshots:
- MAC addresses are locally administered (02:…), so they can't belong to real hardware.
- The "credentials" are the classic fake hunter2.
- Large transfers use big captured segments (like macOS LRO captures) with
  short snap lengths, so the file stays under a megabyte.

Story: normal browsing and a video call; at 20 s a login form is posted over
plain HTTP; at 35 s a smart TV on the LAN port-scans this Mac; from 50 s one
outside host starts pulling most of the bandwidth.

Run:  .venv/bin/python scripts/make_demo_pcap.py
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
)

OUT = Path(__file__).resolve().parents[1] / "samples" / "demo.pcap"
T0 = 1_762_869_600.0  # a fixed start time so the file is reproducible
DURATION = 90
SNAP = 96

ME, ME_MAC = "192.168.1.23", "02:00:00:00:00:23"
GW, GW_MAC = "192.168.1.1", "02:00:00:00:00:01"
PHONE, PHONE_MAC = "192.168.1.42", "02:00:00:00:00:42"
TV, TV_MAC = "192.168.1.77", "02:00:00:00:00:77"
PRINTER, PRINTER_MAC = "192.168.1.30", "02:00:00:00:00:30"
DNS_SERVER = "1.1.1.1"

# (name, ip, inbound bytes/s) for steady background traffic.
SITES = [
    ("zoom.us", "170.114.52.2", 380_000),
    ("github.com", "140.82.112.3", 60_000),
    ("www.bbc.co.uk", "212.58.237.1", 30_000),
    ("www.spiegel.de", "128.65.210.8", 22_000),
    ("www.yahoo.co.jp", "182.22.25.252", 18_000),
    ("www.uol.com.br", "200.147.67.142", 14_000),
    ("www.naver.com", "223.130.200.104", 12_000),
    ("www.sydney.edu.au", "129.78.5.8", 9_000),
    ("api.spotify.com", "35.186.224.25", 40_000),
]
HOG = ("dl.mirrorhub.example", "5.79.71.205")
SHOP = ("shop.example", "93.184.215.14")

rng = random.Random(42)
records: list[tuple[float, bytes, int]] = []


def emit(ts: float, pkt, wirelen: int | None = None, snap: int | None = None) -> None:
    raw = bytes(pkt)
    wl = max(wirelen or len(raw), len(raw))
    if snap is not None:
        raw = raw[:snap]
    records.append((ts, raw, wl))


def to_me(src_ip):
    return Ether(src=GW_MAC, dst=ME_MAC) / IP(src=src_ip, dst=ME, ttl=55)


def from_me(dst_ip):
    return Ether(src=ME_MAC, dst=GW_MAC) / IP(src=ME, dst=dst_ip, ttl=64)


def client_hello(name: str) -> bytes:
    n = name.encode()
    ext = (b"\x00\x00" + (len(n) + 5).to_bytes(2, "big") + (len(n) + 3).to_bytes(2, "big")
           + b"\x00" + len(n).to_bytes(2, "big") + n)
    body = (b"\x03\x03" + bytes(rng.randrange(256) for _ in range(32)) + b"\x00"
            + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def app_data(n: int = 60) -> bytes:
    return b"\x17\x03\x03" + n.to_bytes(2, "big") + bytes(rng.randrange(256) for _ in range(n))


def resolve(ts: float, name: str, ip: str, port: int) -> None:
    qid = rng.randrange(65535)
    emit(ts, from_me(DNS_SERVER) / UDP(sport=port, dport=53) /
         DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    emit(ts + 0.012, to_me(DNS_SERVER) / UDP(sport=53, dport=port) /
         DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
             an=[DNSRR(rrname=name, ttl=300, rdata=ip)]))


def open_tls(ts: float, name: str, ip: str, sport: int) -> None:
    emit(ts, from_me(ip) / TCP(sport=sport, dport=443, flags="S", seq=1000, window=65535))
    emit(ts + 0.02, to_me(ip) / TCP(sport=443, dport=sport, flags="SA", seq=5000, ack=1001))
    emit(ts + 0.021, from_me(ip) / TCP(sport=sport, dport=443, flags="A", seq=1001, ack=5001))
    emit(ts + 0.022, from_me(ip) / TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=5001)
         / Raw(client_hello(name)))


def mdns_announce(ts: float, ip: str, mac: str, host: str) -> None:
    emit(ts, Ether(src=mac, dst="01:00:5e:00:00:fb") / IP(src=ip, dst="224.0.0.251", ttl=255) /
         UDP(sport=5353, dport=5353) /
         DNS(qr=1, aa=1, an=[DNSRR(rrname=f"{host}.local", type="A", ttl=120, rdata=ip)]))


def build() -> None:
    # Gateway and home devices announce themselves.
    emit(T0 + 0.2, Ether(src=GW_MAC, dst=ME_MAC) / ARP(op=2, psrc=GW, hwsrc=GW_MAC, pdst=ME,
                                                       hwdst=ME_MAC))
    mdns_announce(T0 + 0.6, PHONE, PHONE_MAC, "iPhone")
    mdns_announce(T0 + 0.9, TV, TV_MAC, "Living-Room-TV")
    mdns_announce(T0 + 1.3, PRINTER, PRINTER_MAC, "Office-Printer")

    # Open every site once, then stream steady traffic.
    ports = {}
    for i, (name, ip, _) in enumerate(SITES):
        t = T0 + 1.5 + i * 0.35
        resolve(t, name, ip, 53000 + i)
        sport = 51000 + i
        ports[ip] = sport
        open_tls(t + 0.05, name, ip, sport)

    seq = {ip: 5001 for _, ip, _ in SITES}
    for s in range(3, DURATION):
        for _name, ip, bps in SITES:
            jitter = rng.uniform(0.7, 1.3)
            total = int(bps * jitter)
            chunks = max(1, total // 48_000)
            for _ in range(chunks):
                ts = T0 + s + rng.random()
                size = total // chunks
                emit(ts, to_me(ip) / TCP(sport=443, dport=ports[ip], flags="PA", seq=seq[ip],
                                         ack=2000) / Raw(app_data()), wirelen=size + 66, snap=SNAP)
                seq[ip] += size
                emit(ts + 0.004, from_me(ip) / TCP(sport=ports[ip], dport=443, flags="A",
                                                   seq=2000, ack=seq[ip]))
        # A little phone chatter and a ping now and then.
        if s % 4 == 0:
            emit(T0 + s + 0.5, Ether(src=PHONE_MAC, dst=ME_MAC) / IP(src=PHONE, dst=ME) /
                 UDP(sport=62000, dport=7000) / Raw(b"\x00" * 120), wirelen=4_000)
        if s % 10 == 5:
            emit(T0 + s + 0.3, from_me(DNS_SERVER) / ICMP(type=8, id=7, seq=s))
            emit(T0 + s + 0.318, to_me(DNS_SERVER) / ICMP(type=0, id=7, seq=s))
        if s % 15 == 2:
            emit(T0 + s + 0.7, Ether(src=PRINTER_MAC, dst="01:00:5e:7f:ff:fa") /
                 IP(src=PRINTER, dst="239.255.255.250") / UDP(sport=1900, dport=1900) /
                 Raw(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n"))

    # 20 s: a login form posted over plain HTTP (fake credentials).
    t = T0 + 20
    resolve(t, SHOP[0], SHOP[1], 53100)
    emit(t + 0.05, from_me(SHOP[1]) / TCP(sport=52000, dport=80, flags="S", seq=1))
    emit(t + 0.07, to_me(SHOP[1]) / TCP(sport=80, dport=52000, flags="SA", seq=9, ack=2))
    body = b"user=demo%40example.com&password=hunter2"
    req = (b"POST /account/login HTTP/1.1\r\nHost: shop.example\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    emit(t + 0.08, from_me(SHOP[1]) / TCP(sport=52000, dport=80, flags="PA", seq=2, ack=10) /
         Raw(req))
    emit(t + 0.12, to_me(SHOP[1]) / TCP(sport=80, dport=52000, flags="PA", seq=10,
                                        ack=2 + len(req)) /
         Raw(b"HTTP/1.1 302 Found\r\nLocation: /account\r\n\r\n"))

    # 35 s: the smart TV port-scans this Mac (this Mac answers with resets).
    ports_scanned = list(range(1, 1025))
    rng.shuffle(ports_scanned)
    for i, port in enumerate(ports_scanned[:214]):
        ts = T0 + 35 + i * 0.035
        emit(ts, Ether(src=TV_MAC, dst=ME_MAC) / IP(src=TV, dst=ME, ttl=64) /
             TCP(sport=40000 + (i % 50), dport=port, flags="S", seq=rng.randrange(2**31)))
        emit(ts + 0.0005, Ether(src=ME_MAC, dst=TV_MAC) / IP(src=ME, dst=TV) /
             TCP(sport=port, dport=40000 + (i % 50), flags="RA", seq=0, ack=1))

    # 50 s: one outside host starts pulling ~6 MB/s.
    t = T0 + 49.5
    resolve(t, HOG[0], HOG[1], 53200)
    open_tls(t + 0.05, HOG[0], HOG[1], 52500)
    hseq = 5001
    for s in range(50, DURATION):
        ramp = min(1.0, (s - 49) / 4)
        per_sec = int(6_200_000 * ramp * rng.uniform(0.9, 1.1))
        n = max(4, per_sec // 64_000)
        for k in range(n):
            ts = T0 + s + k / n
            size = per_sec // n
            emit(ts, to_me(HOG[1]) / TCP(sport=443, dport=52500, flags="A", seq=hseq, ack=2000) /
                 Raw(app_data()), wirelen=size + 66, snap=SNAP)
            hseq += size
            if k % 8 == 0:
                emit(ts + 0.002, from_me(HOG[1]) / TCP(sport=52500, dport=443, flags="A",
                                                       seq=2000, ack=hseq))


def write() -> None:
    records.sort(key=lambda r: r[0])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw, wirelen in records:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(raw), wirelen))
            fh.write(raw)
    size = OUT.stat().st_size
    print(f"Wrote {OUT.relative_to(OUT.parents[1])}: {len(records)} packets, {size / 1024:.0f} KB")


if __name__ == "__main__":
    build()
    write()
