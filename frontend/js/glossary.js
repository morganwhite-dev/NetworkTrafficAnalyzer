// Plain-English text for everything on the dashboard that has jargon in it.
// One place, so the tooltips, the alert cards and the help panel never disagree.

export const PROTO_TIPS = {
  TLS: "Encrypted web traffic (the padlock). Nobody on the way can read it.",
  QUIC: "Encrypted web traffic used by Chrome, YouTube and Google. Same idea as TLS, newer and faster.",
  TCP: "The reliable-delivery layer under most connections. Plain TCP here means no more detail was visible.",
  UDP: "Quick, no-handshake messages. Used for video calls, games and lookups.",
  DNS: "Looking up a site's address from its name, like a phone book. Every site visit starts with one.",
  HTTP: "Web traffic with NO encryption. Anything sent this way can be read by anyone on the network.",
  ICMP: "Ping. Devices checking whether another device is reachable.",
  ARP: "“Who on this Wi-Fi has this address?” Devices finding each other.",
  mDNS: "Devices announcing themselves on your Wi-Fi (printers, Apple TV, AirPlay).",
  SSDP: "Devices announcing themselves on your Wi-Fi (smart TVs, speakers).",
  DHCP: "A device asking the router for an address when it joins the Wi-Fi.",
  SSH: "Encrypted remote login to another computer.",
  Other: "Traffic the analyzer doesn't decode.",
};

export const SEVERITY_TIPS = {
  critical:
    "Critical: something sensitive was exposed, like a password sent without encryption. Look at it now.",
  high: "High: behaviour that is very likely unwanted, like a port scan or a device hogging the network.",
  medium: "Medium: unusual, but often harmless. Worth a glance.",
  low: "Low: for your information. Usually normal.",
  info: "Info: nothing wrong, just noted.",
};

// What each alert means and what to do about it, keyed by the alert's `kind`.
export const ALERT_INFO = {
  port_scan: {
    means:
      "One device is trying lots of “doors” (ports) on another to find which are open. It is how attackers look for a way in.",
    todo: "If you don't know the scanner, treat it as hostile and disconnect it. Smart TVs and printers sometimes do this when they are broken or infected.",
  },
  host_sweep: {
    means:
      "One device is knocking on every address on your network to see who is home.",
    todo: "Normal for a network-scanning app you ran yourself. Otherwise find out which device it is.",
  },
  cleartext_credentials: {
    means:
      "A password, login or access token was sent over the network with no encryption, so anyone listening could read it.",
    todo: "Change that password, and use the https:// version of the site or a different app. Click Reveal to see exactly what was exposed.",
  },
  cleartext_session: {
    means:
      "A very old, unencrypted remote-login session (Telnet) is open. Everything typed, including passwords, is readable.",
    todo: "Switch to SSH, which is encrypted.",
  },
  traffic_spike: {
    means:
      "Total traffic jumped far above your normal level and stayed there for a few seconds.",
    todo: "Usually a big download or update. If you weren't doing anything, check the top talker named in the alert.",
  },
  bandwidth_hog: {
    means: "One server is using most of your network speed.",
    todo: "Fine for streaming, backups and updates. If you don't recognise the host, find which app is talking to it.",
  },
  arp_spoof: {
    means:
      "A device is claiming another device's identity on your Wi-Fi, often your router's. That is how someone intercepts traffic.",
    todo: "Treat as serious. Disconnect from this network if you're on public Wi-Fi.",
  },
  mac_change: {
    means:
      "A device's hardware address changed. Phones do this on purpose for privacy (Private Wi-Fi Address).",
    todo: "Normally nothing. Only look closer if it comes with other alerts.",
  },
  dns_tunnel: {
    means:
      "Something is sending data out disguised as name lookups. It is a way to smuggle data past firewalls.",
    todo: "Find the device named in the alert. Some security software and CDNs trigger this innocently.",
  },
  rogue_dhcp: {
    means:
      "Two devices are both handing out network addresses. A fake one can send your traffic through itself.",
    todo: "Find the second server. A forgotten extra router is the usual cause.",
  },
  rogue_ra: {
    means:
      "A second IPv6 router appeared on your network. A fake one can redirect your traffic.",
    todo: "Find the second device. A new router or access point is the usual cause.",
  },
  vpn_leak: {
    means:
      "Your VPN is on, but some traffic is going out around it, so it isn't protected.",
    todo: "Check your VPN's kill switch or leak-protection setting, or reconnect it.",
  },
};

export const PANEL_TIPS = {
  network:
    "Map: your Mac, router and devices on the left, internet servers on the right. Flows: who uses your bandwidth. Wi-Fi: how healthy your connection is.",
  alerts:
    "Things that look wrong, explained in plain words. Click one to see the packets involved.",
  bandwidth: "How fast data is moving over the last minute. Red means a spike.",
  protocols:
    "What kinds of traffic you have, by share of packets (not by size). Hover a name for what it means.",
  geo: "Where in the world the servers you talk to are. Looked up offline, nothing leaves your Mac.",
  packets:
    "Every packet captured, like Wireshark. You don't need this day to day. Click a device or alert to filter it here.",
  inspector:
    "Click any packet to see it decoded, in plain words, and as raw bytes.",
};

const WHAT = {
  TLS: "encrypted web traffic",
  QUIC: "encrypted web traffic",
  DNS: "a name lookup",
  HTTP: "unencrypted web traffic",
  ICMP: "a ping",
  ARP: "a “who is on this Wi-Fi?” query",
  TCP: "a connection message",
  UDP: "a quick message",
  mDNS: "a device announcement",
  SSDP: "a device announcement",
  DHCP: "an address request",
  SSH: "encrypted remote-login traffic",
};

/** One plain sentence for a packet row: "This Mac sent encrypted web traffic to zoom.us." */
export function plainSummary(row, labelFor = (ip) => ip) {
  const what = WHAT[row.proto] || `${row.proto} traffic`;
  return `${labelFor(row.src)} sent ${what} to ${labelFor(row.dst)}.`;
}

/** Wording for the protocol tooltip, falling back to nothing for unknown names. */
export function protoTip(name) {
  return PROTO_TIPS[name] || "";
}

/** Short explanation for the alert's kind, or null when we have none. */
export function alertInfo(kind) {
  return ALERT_INFO[kind] || null;
}
