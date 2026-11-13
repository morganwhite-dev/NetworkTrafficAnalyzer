import { fmtPct, fmtRate } from "./format.js";

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
  slow_wifi: {
    means:
      "The Wi-Fi between this Mac and the router is slow: the router takes too long to answer, or misses some of the checks.",
    todo: "See the tips above. The Wi-Fi tab shows the live numbers.",
  },
  slow_internet: {
    means:
      "Your Wi-Fi is fine, but the internet past the router is slow. The problem is the modem or your provider.",
    todo: "See the tips above. If it lasts, check your provider's status page.",
  },
  wifi_hiccups: {
    means:
      "Most of the time the Wi-Fi is quick, but now and then the router takes a long time to answer. Those moments are when pages hang and calls freeze.",
    todo: "Usually another device grabbing the Wi-Fi in bursts, or interference. Moving closer to the router helps.",
  },
  heavy_use: {
    means:
      "This Mac is moving a lot of data, enough to slow the connection for everything else on it.",
    todo: "Fine if you're downloading or streaming on purpose. If not, quit or pause the app named above.",
  },
};

export const PANEL_TIPS = {
  network:
    "Map: your Mac, router and devices on the left, internet servers on the right. Flows: who uses your bandwidth. World: where those servers are. Wi-Fi: how healthy your connection is.",
  alerts:
    "Things that look wrong, explained in plain words. Open one with its ? for the numbers and what to do. Click it to see the packets involved.",
  traffic:
    "The line is how fast data is moving over the last minute (red means a spike). The bar underneath is what kinds of traffic it is, by share of packets. Hover a colour for what it means.",
  packets:
    "Every packet captured, like Wireshark. You don't need this day to day. Clicking a device or an alert opens it, filtered.",
  inspector: "Click any packet to see it decoded, in plain words, and as raw bytes.",
};

/**
 * The headline numbers for an alert, shown big at the top of its expanded row:
 * [{ value, label, red? }]. Built from the alert's `detail`, so they update in place.
 */
function ms(v) {
  return v == null ? "—" : `${Math.round(v)} ms`;
}

export function alertNumbers(alert, labelFor = (ip) => ip) {
  const d = alert.detail || {};
  const out = [];
  switch (alert.kind) {
    case "bandwidth_hog":
      if (d.bps != null) out.push({ value: fmtRate(d.bps), label: alert.ended ? "last" : "now", red: !alert.ended });
      if (d.share != null) out.push({ value: fmtPct(d.share), label: "of traffic" });
      if (d.vs_normal != null)
        out.push({ value: `+${Math.round(d.vs_normal)}%`, label: "vs normal" });
      break;
    case "slow_wifi":
    case "slow_internet":
    case "wifi_hiccups":
      out.push({ value: ms(d.gw_ms), label: "router", red: alert.kind === "slow_wifi" });
      out.push({ value: ms(d.net_ms), label: "internet", red: alert.kind === "slow_internet" });
      if (d.mac_bps != null)
        out.push({ value: fmtRate(d.mac_bps), label: "this Mac uses", red: !!d.this_mac });
      break;
    case "heavy_use":
      if (d.bps != null) out.push({ value: fmtRate(d.bps), label: "this Mac", red: true });
      if (d.peak != null) out.push({ value: fmtRate(d.peak), label: "peak" });
      if (d.of_link != null) out.push({ value: fmtPct(d.of_link), label: "of Wi-Fi link" });
      break;
    case "port_scan":
      if (d.ports != null) out.push({ value: String(d.ports), label: "ports probed", red: true });
      if (d.target) out.push({ value: labelFor(d.target), label: "target" });
      break;
    case "cleartext_credentials":
      out.push({ value: d.field || "secret", label: "field", red: true });
      out.push({ value: "none", label: "encryption" });
      break;
    case "traffic_spike":
      if (d.bps != null) out.push({ value: fmtRate(d.bps), label: alert.ended ? "last" : "now", red: !alert.ended });
      if (d.baseline != null) out.push({ value: fmtRate(d.baseline), label: "normal" });
      break;
    case "dns_tunnel":
      if (d.domain) out.push({ value: d.domain, label: "domain", red: true });
      break;
    default:
      break;
  }
  return out;
}

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

const FLAG_WORDS = [
  [/^SYN$/, "Opening a connection"],
  [/^SYN, ACK$/, "Accepting a connection"],
  [/FIN/, "Closing the connection"],
  [/RST/, "Connection cut off"],
];

/**
 * What a packet is doing, in a few plain words, for the packet list. The technical
 * line stays in the hover text and the inspector.
 */
export function plainInfo(row, labelFor = (ip) => ip) {
  const info = String(row.info || "");
  const m = info.match(/\[([A-Z, ]+)\].*len=(\d+)/);
  if (row.proto === "TCP" && m) {
    const [, flags, len] = m;
    for (const [re, words] of FLAG_WORDS) if (re.test(flags)) return words;
    if (Number(len) > 0) return `Data · ${Number(len).toLocaleString()} bytes`;
    return "“Got it”: confirming data arrived";
  }
  let x;
  if ((x = info.match(/^Client Hello · (.+)$/))) return `Starting a secure connection to ${x[1]}`;
  if ((x = info.match(/^Application Data · (\d+) bytes$/)))
    return `Encrypted data · ${Number(x[1]).toLocaleString()} bytes`;
  if (/^Handshake/.test(info)) return "Setting up encryption";
  if (/^Change Cipher Spec/.test(info)) return "Switching on encryption";
  if (/^Alert/.test(info)) return "Encryption notice (often a goodbye)";
  if (info === "QUIC Initial") return "Starting a fast encrypted connection";
  if (info === "QUIC short header") return "Encrypted data (QUIC)";
  if ((x = info.match(/^Query \S+ (.+)$/))) return `Looking up ${x[1]}`;
  if ((x = info.match(/^Response \S+ (\S+) · no such name/))) return `${x[1]} doesn't exist`;
  if ((x = info.match(/^Response \S+ (\S+) → (\S+)/))) return `${x[1]} is at ${labelFor(x[2])}`;
  if ((x = info.match(/^Response \S+ (\S+)/))) return `Answer about ${x[1]}`;
  if (/^Echo request/.test(info)) return "Ping: are you there?";
  if (/^Echo reply/.test(info)) return "Ping reply: yes";
  if ((x = info.match(/^Neighbor Solicitation · who has (\S+)/)))
    return `Who has ${labelFor(x[1])}?`;
  if (/^Neighbor Advertisement/.test(info)) return "“That's me” (address answer)";
  if (/^Router Advertisement/.test(info)) return "Router announcing itself";
  if (row.proto === "mDNS" || row.proto === "SSDP") return "A device announcing itself";
  if (row.proto === "UDP" && (x = info.match(/len=(\d+)/)))
    return `Quick message · ${Number(x[1]).toLocaleString()} bytes`;
  return info;
}

/** Wording for the protocol tooltip, falling back to nothing for unknown names. */
export function protoTip(name) {
  return PROTO_TIPS[name] || "";
}

/** Short explanation for the alert's kind, or null when we have none. */
export function alertInfo(kind) {
  return ALERT_INFO[kind] || null;
}
