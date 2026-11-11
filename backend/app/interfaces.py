"""macOS interface discovery: names, addresses, default route, capture access.

External tools are called with absolute paths and argument lists (never a
shell), and interface names are validated against Scapy's own list.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass

NETWORKSETUP = "/usr/sbin/networksetup"
ROUTE = "/sbin/route"
IFCONFIG = "/sbin/ifconfig"
IFACE_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


@dataclass
class Iface:
    name: str
    label: str
    ipv4: list[str]
    ipv6: list[str]
    netmask: str | None
    up: bool

    def to_dict(self) -> dict:
        return {"name": self.name, "label": self.label, "ipv4": self.ipv4, "ipv6": self.ipv6,
                "up": self.up, "kind": kind_of_iface(self.name)}


def _run(args: list[str], timeout: float = 3.0) -> str:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def kind_of_iface(name: str) -> str:
    if name.startswith("utun") or name.startswith("ipsec") or name.startswith("tun"):
        return "vpn"
    if name.startswith("lo"):
        return "loopback"
    if name.startswith(("bridge", "awdl", "llw", "anpi", "gif", "stf", "ap", "nan")):
        return "system"
    return "network"


def hardware_labels() -> dict[str, str]:
    """{'en0': 'Wi-Fi', 'en5': 'USB 10/100/1000 LAN', …} from networksetup."""
    if sys.platform != "darwin":
        return {}
    labels, port = {}, None
    for line in _run([NETWORKSETUP, "-listallhardwareports"]).splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            labels[line.split(":", 1)[1].strip()] = port
            port = None
    return labels


def scapy_ifaces() -> list[str]:
    from scapy.all import get_if_list
    try:
        return list(get_if_list())
    except Exception:  # noqa: BLE001
        return []


def valid_iface(name: str | None) -> bool:
    return bool(name and IFACE_NAME.match(name) and name in scapy_ifaces())


def addresses(name: str) -> tuple[list[str], list[str], str | None, bool]:
    if not IFACE_NAME.match(name):
        return [], [], None, False
    text = _run([IFCONFIG, name]) if os.path.exists(IFCONFIG) else ""
    v4, v6, mask = [], [], None
    up = "<UP" in text or ",UP," in text
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            v4.append(parts[1])
            if "netmask" in parts:
                raw = parts[parts.index("netmask") + 1]
                try:
                    mask = str(ipaddress.IPv4Address(int(raw, 16))) if raw.startswith("0x") \
                        else raw
                except ValueError:
                    mask = None
        elif line.startswith("inet6 "):
            v6.append(line.split()[1].split("%")[0])
    return v4, v6, mask, up


def list_interfaces() -> list[Iface]:
    labels = hardware_labels()
    out = []
    for name in scapy_ifaces():
        v4, v6, mask, up = addresses(name)
        label = labels.get(name) or {"lo0": "Loopback"}.get(name) or (
            "VPN tunnel" if kind_of_iface(name) == "vpn" else name)
        out.append(Iface(name, label, v4, v6, mask, up))
    order = {"network": 0, "vpn": 1, "loopback": 2, "system": 3}
    out.sort(key=lambda i: (order[kind_of_iface(i.name)], not i.ipv4, i.name))
    return out


def default_iface() -> str | None:
    names = scapy_ifaces()
    if "en0" in names:
        return "en0"
    for i in list_interfaces():
        if i.up and i.ipv4 and kind_of_iface(i.name) == "network":
            return i.name
    return names[0] if names else None


def default_route() -> dict[str, str | None]:
    """{'gateway': '192.168.1.1', 'interface': 'en0'} (or utunN when a VPN owns it)."""
    text = _run([ROUTE, "-n", "get", "default"]) if os.path.exists(ROUTE) else ""
    info: dict[str, str | None] = {"gateway": None, "interface": None}
    for line in text.splitlines():
        key, _, value = line.strip().partition(":")
        if key in ("gateway", "interface"):
            info[key] = value.strip() or None
    return info


def network_of(ipv4: str, mask: str | None) -> str | None:
    try:
        return str(ipaddress.ip_network(f"{ipv4}/{mask or '255.255.255.0'}", strict=False))
    except ValueError:
        return None


def capture_access() -> tuple[bool, str]:
    """Can this process open a packet capture right now? (ok, hint)"""
    if os.geteuid() == 0:
        return True, "Running as root."
    if sys.platform == "darwin":
        if os.access("/dev/bpf0", os.R_OK):
            return True, "BPF devices are readable (ChmodBPF)."
        return False, ("Live capture needs access to /dev/bpf*. Install Wireshark's ChmodBPF "
                       "helper, or start the app with sudo. Replay and .pcap upload work "
                       "without it.")
    return False, ("Live capture needs root or CAP_NET_RAW. Replay and .pcap upload work "
                   "without it.")
