"""What is this address? What the app has seen, plus (for internet addresses) who owns it.

Local knowledge comes first: the app already knows which addresses are this Mac, the router
and the devices at home, and it has seen names for many servers in your DNS answers and TLS
handshakes. For an address on the internet it then asks, only when you click one:

- the system's reverse DNS (what the address calls itself), and
- ipwho.is (https, no key) for the owning organisation, network number and location.

Both are skipped for private addresses, and the owner lookup can be switched off with
``--no-ip-lookup``. Results are cached for an hour. Nothing here runs in the background.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any

OWNER_URL = ("https://ipwho.is/{ip}?fields=success,country,country_code,region,city,"
             "connection")
MAX_BODY = 32 * 1024
CACHE_SECONDS = 3600
CACHE_SIZE = 512

# Plain-English notes for big networks, matched against the owner, domain and host names.
# (words to look for, what to tell the user)
SERVICE_NOTES: list[tuple[tuple[str, ...], str]] = [
    (("google", "1e100.net", "youtube"),
     "Google: search, YouTube, Gmail, Chrome, Android and Google Cloud."),
    (("apple", "icloud"),
     "Apple: iCloud, the App Store, software updates, Messages and Siri."),
    (("cloudflare",),
     "Cloudflare: a CDN. It sits in front of millions of websites, so this could be any of them."),
    (("amazon", "aws", "cloudfront"),
     "Amazon Web Services: cloud hosting that a huge number of apps and sites run on."),
    (("akamai",), "Akamai: a CDN that delivers websites, video and downloads."),
    (("fastly",), "Fastly: a CDN that delivers websites and apps."),
    (("microsoft", "azure", "office365"),
     "Microsoft: Windows, Office, Teams, Outlook and the Azure cloud."),
    (("meta platforms", "facebook", "instagram", "whatsapp"),
     "Meta: Facebook, Instagram and WhatsApp."),
    (("netflix",), "Netflix: streaming video."),
    (("github",), "GitHub: code hosting."),
    (("anthropic",), "Anthropic: the company behind Claude."),
    (("spotify",), "Spotify: music streaming."),
    (("zoom",), "Zoom: video calls."),
    (("digitalocean", "linode", "ovh", "hetzner", "vultr"),
     "A hosting company: someone rents servers here, so it could be almost anything."),
]

# Router makers that mostly show up on shared networks run by someone else.
MANAGED = re.compile(r"(routerboard|mikrotik|cisco|meraki|aruba|ruckus|ubiquiti|juniper|"
                     r"fortinet|extreme|cambium|hewlett)", re.IGNORECASE)

_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ipinfo")
_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_cache_lock = threading.Lock()


def fetch_owner(ip: str, timeout: float = 4.0) -> dict[str, Any] | None:
    """Owner, network number and place for a public address, or None if it can't be found."""
    # `ip` was parsed by ipaddress, and the URL is a fixed https one, so nothing here can be
    # steered to another scheme or host.
    req = urllib.request.Request(  # noqa: S310
        OWNER_URL.format(ip=ip), headers={"User-Agent": "network-traffic-analyzer"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read(MAX_BODY))
    if not data.get("success", False):
        return None
    conn = data.get("connection") or {}
    return {
        "org": conn.get("org") or conn.get("isp") or "",
        "isp": conn.get("isp") or "",
        "asn": f"AS{conn['asn']}" if conn.get("asn") else "",
        "domain": conn.get("domain") or "",
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "country": data.get("country") or "",
        "cc": data.get("country_code") or "",
    }


def reverse_name(ip: str) -> str | None:
    """What the address calls itself in DNS (its PTR record), if it has one."""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return name if name and name != ip else None


def service_note(*texts: str) -> str:
    hay = " ".join(t.lower() for t in texts if t)
    for words, note in SERVICE_NOTES:
        if any(w in hay for w in words):
            return note
    return ""


def address_kind(ip: str) -> str:
    """A plain description of the address itself."""
    a = ipaddress.ip_address(ip)
    if a.is_loopback:
        return "a loopback address (this Mac talking to itself)"
    if a.is_link_local:
        return "a link-local address (only works inside your network)"
    if a.is_private:
        return "a private address (only works inside your network)"
    if a.is_multicast:
        return "a multicast address (one message for a whole group of devices)"
    return "a public internet address"


def _bytes(n: int) -> str:
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


def explain(ip: str, local: dict[str, Any], owner: dict[str, Any] | None,
            hostname: str | None, status: str) -> dict[str, Any]:
    """Turn what we know into a title, a plain sentence and a list of facts."""
    kind = local.get("kind") or "other"
    # Its own name (what it called itself), not the label the map made up for it.
    name = local.get("own_name", local.get("name")) or ""
    if name == ip:
        name = ""
    app = local.get("app") or ""
    maker = local.get("maker") or ""
    org = (owner or {}).get("org") or local.get("owner") or ""
    place = ", ".join(x for x in ((owner or {}).get("city"), (owner or {}).get("region"),
                                  (owner or {}).get("country")) if x)
    if not place:
        place = ", ".join(x for x in (local.get("city"), local.get("country")) if x)
    note = service_note(org, (owner or {}).get("domain", ""), hostname or "", name)

    if kind == "self":
        title = "This Mac"
        summary = "This is your Mac. Every connection in this app starts or ends here."
    elif kind == "gateway":
        title = "Your router"
        summary = ("This is your router, the box that connects your network to the "
                   "internet. All your internet traffic passes through it.")
        if maker:
            summary += f" Made by {maker}."
        if MANAGED.search(maker):
            summary += (" That brand is usually run by a building, campus or office IT team, so "
                        "this is probably a shared network you can't log in to.")
    elif kind == "lan" or (kind == "other" and not ipaddress.ip_address(ip).is_global):
        if name:
            title = name
            summary = f"A device on your network that calls itself {name}"
            summary += f", made by {maker}." if maker else "."
        elif local.get("private_mac"):
            title = "Private device"
            summary = ("A device on your network that hides its real hardware address. Phones, "
                       "tablets and laptops do this for privacy, so it is almost certainly one "
                       "of those. Its maker can't be looked up.")
        elif maker:
            title = f"{maker} device"
            summary = (f"A device on your network made by {maker}. It didn't announce a name, "
                       "so this is as specific as it gets.")
        else:
            title = "A device on your network"
            summary = ("A device on your network that didn't announce a name, and whose maker "
                       "isn't in the lookup table.")
        if len(local.get("addrs") or []) > 1:
            summary += f" It uses {len(local['addrs'])} addresses; they're shown as one device."
    else:
        who = org or hostname or name or app
        title = name or org or hostname or (f"{app} server" if app else ip)
        summary = f"A server on the internet{f', run by {org}' if org else ''}"
        if place:
            summary += f", in {place}"
        summary += "."
        if note:
            summary += f" {note}"
        if name and name != title:
            summary += f" Your Mac reached it as {name}."
        if app:
            summary += f" On this Mac, {app} is the app talking to it."
        if not who:
            summary += (" I couldn't find out who runs it" +
                        (" (the lookup is turned off)." if status == "disabled"
                         else " (no internet, or the lookup service didn't answer)."
                         if status == "unreachable" else "."))

    facts: list[dict[str, str]] = []

    def add(label: str, value: str | None) -> None:
        if value:
            facts.append({"label": label, "value": value})

    if not ipaddress.ip_address(ip).is_global:       # the card header already shows a public one
        add("Address", f"{ip}, {address_kind(ip)}")
    if name and name != title:
        add("Name seen", name)
    add("Used by", app)
    add("Made by", maker if kind in ("lan", "gateway") else "")
    others = [a for a in (local.get("addrs") or []) if a != ip]
    if others:
        add("Also uses", ", ".join(others[:4]) + (" …" if len(others) > 4 else ""))
    add("Owner", org)
    if (owner or {}).get("asn"):
        add("Network", f"{owner['asn']}" + (f" ({owner['isp']})" if owner.get("isp")
                                           and owner["isp"] != org else ""))
    add("Website", (owner or {}).get("domain"))
    add("Reverse DNS", hostname)
    add("Location", place)
    add("Hardware address", local.get("mac"))
    if local.get("packets"):
        add("Traffic", f"{local['packets']:,} packets · {_bytes(local.get('bytes_in', 0))} in · "
                       f"{_bytes(local.get('bytes_out', 0))} out")
    if local.get("first"):
        add("First seen", time.strftime("%H:%M:%S", time.localtime(local["first"])))
    return {"ip": ip, "kind": kind, "title": title, "summary": summary, "facts": facts,
            "status": status}


def cached_owner(ip: str) -> str:
    """The owner found when someone clicked this address earlier, if any (no lookup)."""
    with _cache_lock:
        hit = _cache.get(ip)
    return ((hit[1].get("owner") or {}).get("org") or "") if hit else ""


def lookup(ip: str, local: dict[str, Any], enabled: bool = True) -> dict[str, Any]:
    """Everything we can say about `ip`. Never raises: a failed lookup just says less."""
    addr = ipaddress.ip_address(ip)
    owner: dict[str, Any] | None = None
    hostname: str | None = None
    if not addr.is_global:
        status = "private"
    elif not enabled:
        status = "disabled"
    else:
        with _cache_lock:
            hit = _cache.get(ip)
            if hit and time.time() - hit[0] < CACHE_SECONDS:
                _cache.move_to_end(ip)
                owner, hostname = hit[1]["owner"], hit[1]["hostname"]
                status = "ok"
            else:
                hit = None
        if hit is None:
            fut_owner = _pool.submit(fetch_owner, ip)
            fut_name = _pool.submit(reverse_name, ip)
            try:
                owner = fut_owner.result(timeout=6)
            except Exception:  # noqa: BLE001 - offline, rate-limited, bad reply: all just "unknown"
                owner = None
            try:
                hostname = fut_name.result(timeout=3)
            except Exception:  # noqa: BLE001
                hostname = None
            status = "ok" if owner else "unreachable"
            if owner:
                with _cache_lock:
                    _cache[ip] = (time.time(), {"owner": owner, "hostname": hostname})
                    while len(_cache) > CACHE_SIZE:
                        _cache.popitem(last=False)
    return explain(ip, local, owner, hostname, status)
