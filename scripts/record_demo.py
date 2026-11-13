"""Record a ~85 second 1920x1080 walkthrough of the LIVE dashboard (real capture on this Mac).

1. Start a live capture on a throwaway port with a known token (needs ChmodBPF or sudo):
       NTA_TOKEN=live-recording-4821xyz scripts/run.sh --port 8004 --start
2. Record (it also makes a little ordinary web traffic of its own so there is always
   something to look at: a few HTTPS and one plain-HTTP request to public sites):
       NTA_URL=http://localhost:8004 NTA_TOKEN=live-recording-4821xyz \
         .venv/bin/python scripts/record_demo.py

During warm-up it runs the Wi-Fi tab's speed test once (about 20 s and a few hundred MB;
NTA_SPEED_TEST=0 skips it), so the slow-network alert in the video is real.

Writes docs/demo/network-traffic-analyzer-demo.mp4 (H.264, from a raw .webm in
docs/demo/raw/). Uses the installed Google Chrome through Playwright and ffmpeg.

Privacy: this records a real network. While recording, the page blurs the names and addresses
of OTHER devices on the Wi-Fi, this Mac's and the router's addresses, hardware addresses, the
hex dump, and anything private on the address card and the Wi-Fi tab. Internet hostnames
are real and stay visible. Always watch the result
before posting it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "docs" / "demo" / "raw"
FINAL = ROOT / "docs" / "demo" / "network-traffic-analyzer-demo.mp4"
BASE = os.environ.get("NTA_URL", "http://localhost:8004")
TOKEN = os.environ.get("NTA_TOKEN", "")
W, H = 1920, 1080
IFACE = os.environ.get("NTA_IFACE", "en0")   # only used to know which addresses to look for
SPEED_TEST = os.environ.get("NTA_SPEED_TEST", "1") != "0"

OVERLAY_JS = """
(() => {
  if (window.__demoOverlay) return;
  window.__demoOverlay = true;
  const cur = document.createElement('div');
  Object.assign(cur.style, {position:'fixed', left:'0px', top:'0px', width:'26px', height:'26px',
    zIndex:'2147483647', pointerEvents:'none', transform:'translate(-100px,-100px)',
    transition:'transform 0.06s linear'});
  cur.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24"><path d="M3 2l7 19 3-8 8-3z" '
    + 'fill="#fff" stroke="#000" stroke-width="1.5" stroke-linejoin="round"/></svg>';
  const ring = document.createElement('div');
  Object.assign(ring.style, {position:'fixed', left:'0px', top:'0px', width:'44px', height:'44px',
    margin:'-22px 0 0 -22px', borderRadius:'50%', border:'3px solid #00f3ff', opacity:'0',
    zIndex:'2147483646', pointerEvents:'none'});
  const cap = document.createElement('div');
  Object.assign(cap.style, {position:'fixed', left:'50%', bottom:'34px',
    transform:'translateX(-50%)', zIndex:'2147483647', pointerEvents:'none',
    padding:'14px 30px', borderRadius:'12px', background:'rgba(8,10,15,0.88)',
    border:'1px solid rgba(0,243,255,0.5)', color:'#e8edf6',
    font:'600 26px/1.3 -apple-system, "Helvetica Neue", Arial, sans-serif',
    letterSpacing:'0.2px', opacity:'0', transition:'opacity 0.45s ease', whiteSpace:'nowrap',
    boxShadow:'0 8px 30px rgba(0,0,0,0.5)'});
  document.documentElement.append(cur, ring, cap);
  document.addEventListener('mousemove', e => {
    cur.style.transform = `translate(${e.clientX - 3}px, ${e.clientY - 2}px)`;
    ring.style.left = e.clientX + 'px'; ring.style.top = e.clientY + 'px';
  }, true);
  document.addEventListener('mousedown', () => {
    ring.style.transition = 'none'; ring.style.opacity = '0.95';
    ring.style.transform = 'scale(0.5)';
    requestAnimationFrame(() => requestAnimationFrame(() => {
      ring.style.transition = 'opacity 0.5s, transform 0.5s'; ring.style.opacity = '0';
      ring.style.transform = 'scale(1.5)';
    }));
  }, true);
  window.__caption = (html) => {
    if (!html) { cap.style.opacity = '0'; return; }
    cap.innerHTML = html; cap.style.opacity = '1';
  };
})();
"""

# Blur everything that would identify other people's devices or hardware. Runs every 150 ms
# because the dashboard rebuilds rows and labels constantly.
PRIVACY_JS = """
(() => {
  if (window.__privacy) return;
  window.__privacy = true;
  const st = document.createElement('style');
  st.textContent = '.pn-blur{filter:blur(7px)!important} .hex{filter:blur(8px)!important}'
    + ' #iface-select{filter:blur(6px)!important}';
  document.head.append(st);
  const PRIV = /^(10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.|fe80|f[cd][0-9a-f]{2}:)/i;
  const strip = (t) => t.trim().replace(/:\\d+$/, '');
  let keys = [];     // names and addresses of other devices: blurred where we find them
  let names = [];    // just the names: the audit only fails on these, not on private addresses
  window.__keys = keys;
  window.__leaks = [];
  const mark = (el, on) => el.classList.toggle('pn-blur', !!on);

  const mask = () => {
    const found = [];
    const foundNames = [];
    for (const n of document.querySelectorAll('.node')) {
      const ip = n.dataset.ip || '';
      const lab0 = n.querySelector('.node-label');
      // Devices on the home slab have centred labels; internet hosts sit in the right column.
      const onSlab = !!lab0 && lab0.getAttribute('text-anchor') === 'middle';
      const other = onSlab && !n.classList.contains('is-self') && n.dataset.key !== 'gw'
        && n.dataset.key !== 'lan-more' && n.dataset.key !== 'others';
      for (const t of n.querySelectorAll('.node-label, .node-sub')) mark(t, other);
      if (other) {
        const lab = (lab0.textContent || '').replace(/\\u2026$/, '');
        const base = lab.replace(/\\s+\\d+$/, '');
        if (base.length >= 4 && !PRIV.test(base)) {
          found.push(base);
          foundNames.push(base);
        }
        if (ip) found.push(ip);
      }
    }
    if (found.length) {
      keys = [...new Set([...keys, ...found])];
      window.__keys = keys;
    }
    if (foundNames.length) names = [...new Set([...names, ...foundNames])];
    // The hover card of another device would show its address and kind: hide the whole card.
    const card = document.querySelector('.hovercard');
    if (card) mark(card, keys.some((k) => (card.textContent || '').includes(k)));
    const sel = '.prow .src, .prow .dst, .insp-summary .meta, .hc-name, .fr-name, .ribbon text';
    for (const el of document.querySelectorAll(sel)) {
      const t = el.textContent || '';
      mark(el, keys.some((k) => t.includes(k)) || PRIV.test(strip(t)));
    }
  };

  // Anything on screen, not blurred, that names another device or this Mac's own addresses.
  const audit = () => {
    const own = (window.__own || []).map((x) => x.toLowerCase());
    const bad = names.map((k) => k.toLowerCase());
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const t = node.nodeValue || '';
      const el = node.parentElement;
      if (t.length < 4 || !el || el.closest('.pn-blur, .hex, #iface-select')) continue;
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height || r.bottom < 0 || r.top > innerHeight) continue;
      const low = t.toLowerCase();
      for (const x of own) {
        if (low.includes(x)) window.__leaks.push(`own address ${x} in .${el.className}: ${t}`);
      }
      for (const k of bad) if (k && low.includes(k)) window.__leaks.push(`device ${k}: ${t}`);
    }
  };

  let queued = false;
  const run = () => { mask(); audit(); };
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; mask(); });
  }).observe(document.body, {subtree: true, childList: true, characterData: true});
  setInterval(run, 250);
  run();
})();
"""

# Private addresses and hardware addresses, anywhere in a piece of text.
PRIV_SOURCE = (r"(^|[^0-9a-f:])(10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:"
               r"|[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5})")

# The newer parts of the dashboard: the address card, the Wi-Fi tab, and the labels
# under This Mac and the router. Shared with scripts/capture_screenshots.py.
EXTRA_JS = """
(() => {
  if (window.__extraPrivacy) return;
  window.__extraPrivacy = true;
  const PRIV = new RegExp(PRIV_SOURCE, 'i');
  const own = () => (window.__own || []).map((x) => x.toLowerCase());
  const blur = (el, on) => el.classList.toggle('pn-blur', !!on);
  // This Mac's and the router's addresses under their labels: a style rule, so a label the
  // map has just redrawn is never visible for a frame.
  const st = document.createElement('style');
  st.textContent = '.node[data-key="self"] .node-sub, .node[data-key="gw"] .node-sub'
    + '{filter:blur(7px)!important}';
  document.head.append(st);
  const risky = (t) => PRIV.test(t) || own().some((x) => t.toLowerCase().includes(x))
    || (window.__keys || []).some((k) => k && t.includes(k));
  const run = () => {
    for (const n of document.querySelectorAll('.node[data-key="self"], .node[data-key="gw"]'))
      for (const t of n.querySelectorAll('.node-sub')) blur(t, true);
    const sel = '.ipcard__ip, .ipcard__title, .ipcard__summary, .ipcard__facts dd, .tile-sub, '
      + '.wifi-note, .prow .src, .prow .dst, '
      + '.verdict, .wifi-help dd, .alert-row .why, .alert-row .explain span, .hc-sub, '
      + '.hovercard div, .prow .info, .insp-summary .meta, .insp-note, .fields .v, .chip, '
      + '#nv-stat, .drawer__filter, #filter-chip-slot, .slab-label';
    for (const el of document.querySelectorAll(sel)) blur(el, risky(el.textContent || ''));
    // A card about another device names it in the title, and the cards for This Mac and the
    // router name the internet provider and the city: hide those cards whole.
    const card = document.querySelector('.ipcard');
    if (card && !card.hidden) {
      const title = card.querySelector('.ipcard__title')?.textContent || '';
      blur(card, (window.__keys || []).some((k) => k && title.includes(k))
        || /^(This Mac|Your router)$/.test(title.trim()));
    }
  };
  // Straight after every change too, so a card or row is never readable for a frame.
  new MutationObserver(run).observe(document.body,
    {subtree: true, childList: true, characterData: true});
  setInterval(run, 120);
  run();
})();
""".replace("PRIV_SOURCE", json.dumps(PRIV_SOURCE))

SITES = [
    "https://en.wikipedia.org/wiki/Computer_network",
    "https://github.com/",
    "https://www.python.org/",
    "https://www.mozilla.org/",
    "https://www.cloudflare.com/",
    "http://example.com/",          # plain HTTP, so the "unencrypted" story is real
    "https://www.kernel.org/",
    "https://developer.mozilla.org/",
]


def own_addresses(iface: str) -> list[str]:
    """This Mac's IPv6 addresses (and the /64 they live in) and hardware address on `iface`.
    Used only to check the finished page for leaks, never to display anything."""
    out = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        ["/sbin/ifconfig", iface], capture_output=True, text=True, check=False
    ).stdout
    found: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] == "inet6":
            addr = ipaddress.ip_address(parts[1].split("%")[0])
            found.append(addr.compressed)
            if not addr.is_link_local:
                found.append(":".join(f"{int(h, 16):x}" for h in addr.exploded.split(":")[:4]))
        elif parts[0] == "ether":
            found.append(parts[1].lower())
    return sorted({f for f in found if len(f) >= 8})


class Traffic(threading.Thread):
    """A little ordinary web browsing in the background, so the dashboard always has traffic."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.stop = threading.Event()

    def run(self) -> None:
        i = 0
        while not self.stop.is_set():
            url = SITES[i % len(SITES)]
            i += 1
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "nta-demo/1.0"})
                with urllib.request.urlopen(req, timeout=6) as r:  # noqa: S310 - fixed list above
                    r.read(200_000)
            except Exception:  # noqa: BLE001, S110 - a failed request is fine, it is only traffic
                pass
            self.stop.wait(0.9)


class Director:
    def __init__(self, page: Page) -> None:
        self.page = page
        self.x, self.y = 960, 540
        self.t0 = time.time()

    def caption(self, html: str | None) -> None:
        self.page.evaluate("h => window.__caption(h)", html)

    def pause(self, s: float) -> None:
        self.page.wait_for_timeout(int(s * 1000))

    def goto_xy(self, x: float, y: float, dur: float = 0.8) -> None:
        steps = max(8, int(dur * 40))
        for i in range(1, steps + 1):
            t = i / steps
            e = t * t * (3 - 2 * t)  # smoothstep
            self.page.mouse.move(self.x + (x - self.x) * e, self.y + (y - self.y) * e)
            self.page.wait_for_timeout(int(dur * 1000 / steps))
        self.x, self.y = x, y

    def move(self, selector: str, dur: float = 0.8, dx: float = 0, dy: float = 0) -> bool:
        loc = self.page.locator(selector).first
        try:
            box = loc.bounding_box(timeout=2000)
        except Exception:  # noqa: BLE001
            return False
        if not box:
            return False
        self.goto_xy(box["x"] + box["width"] / 2 + dx, box["y"] + box["height"] / 2 + dy, dur)
        return True

    def click(self, selector: str, dur: float = 0.8) -> bool:
        if not self.move(selector, dur):
            return False
        self.pause(0.15)
        self.page.mouse.down()
        self.pause(0.06)
        self.page.mouse.up()
        return True

    def type(self, selector: str, text: str) -> None:
        self.click(selector)
        self.page.keyboard.press("Meta+a")
        self.page.keyboard.press("Backspace")
        self.page.keyboard.type(text, delay=70)

    def sweep(self, points: list[tuple[float, float]], each: float = 0.9) -> None:
        for x, y in points:
            self.goto_xy(x, y, each)

    def tab(self, selector: str) -> None:
        """Click a tab, then drift off it so its tooltip doesn't sit over the new view."""
        self.click(selector, 0.8)
        self.goto_xy(self.x + 140, self.y + 160, 0.5)

    def at(self, label: str) -> None:
        print(f"  [{time.time() - self.t0:5.1f}s] {label}", flush=True)

    def click_clean_row(self, proto: str | None = None, dur: float = 1.0) -> bool:
        """Click the first packet row that is not blurred (so it involves no other device)."""
        want = proto or ""
        pt = self.page.evaluate(
            """(proto) => {
              const box = document.getElementById('ptable-scroll').getBoundingClientRect();
              for (const r of document.querySelectorAll('.prow')) {
                if (r.querySelector('.pn-blur')) continue;
                if (proto && !r.textContent.includes(proto)) continue;
                const b = r.getBoundingClientRect();
                // fully inside the visible part of the list, clear of the header and the caption
                if (b.height && b.top > box.top + 40 && b.bottom < box.bottom - 90) {
                  // the size/description side: clicking an address would open its card
                  return [b.x + b.width * 0.72, b.y + b.height / 2];
                }
              }
              return null;
            }""",
            want,
        )
        if not pt:
            return False
        self.goto_xy(pt[0], pt[1], dur)
        self.pause(0.15)
        self.page.mouse.down()
        self.pause(0.06)
        self.page.mouse.up()
        return True

    def hover_public_node(self, dur: float = 1.0) -> bool:
        """Hover an internet host on the map (never another device on the home network)."""
        pt = self.page.evaluate(
            """() => {
              const priv =
                /^(10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.|fe80|f[cd][0-9a-f]{2}:)/i;
              const named = [...document.querySelectorAll('.node[data-key^="h:"]')]
                .filter((n) => n.dataset.ip && !priv.test(n.dataset.ip));
              const best = named.find((n) => /[a-z]\\.[a-z]/i.test(n.textContent)) || named[0];
              if (!best) return null;
              const b = best.getBoundingClientRect();
              return [b.x + b.width / 2, b.y + b.height / 2 - 10];
            }"""
        )
        if not pt:
            return False
        self.goto_xy(pt[0], pt[1], dur)
        return True


def wait_for(page: Page, js: str, timeout: float = 150) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if page.evaluate(js):
            return
        time.sleep(0.5)
    raise TimeoutError(js)


HOSTS_OK = ("parseInt((document.querySelector('#nv-stat')?.textContent || '')"
            ".match(/(\\d+) SERVERS/)?.[1] || 0) >= 15")
HAS_HTTP = ("[...document.querySelectorAll('.protolegend span')]"
            ".some(s => /HTTP/.test(s.textContent))")


def to_mp4(src: Path, dst: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed arguments, no shell
        ["ffmpeg", "-y", "-loglevel", "error", "-i", str(src), "-vf", "fps=30,format=yuv420p",
         "-c:v", "libx264", "-preset", "slow", "-crf", "22", "-movflags", "+faststart",
         "-an", str(dst)],
        check=True,
    )


def main() -> int:
    if not TOKEN:
        print("Set NTA_TOKEN to the token the live server was started with.")
        return 2
    RAW.mkdir(parents=True, exist_ok=True)
    traffic = Traffic()
    traffic.start()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True,
                                     args=["--force-device-scale-factor=1", "--hide-scrollbars"])
        # Warm-up context (not recorded): sign in, dismiss the first-run hint, and let the
        # dashboard see enough of the network for the map to be full.
        warm = browser.new_context(viewport={"width": W, "height": H}, color_scheme="dark")
        wp = warm.new_page()
        wp.goto(f"{BASE}/?t={TOKEN}")
        wp.wait_for_selector("#netview svg")
        if wp.locator("#firstrun-dismiss").is_visible():
            wp.click("#firstrun-dismiss")
        print("Warm-up: letting the capture see the network…", flush=True)
        wait_for(wp, HOSTS_OK)
        wait_for(wp, HAS_HTTP, timeout=90)
        wp.click("#tab-wifi")     # starts the Wi-Fi pings so readings exist when we get there
        time.sleep(12)
        if SPEED_TEST:
            # A real speed test: it fills the connection, so the slow-network alert and the
            # speed-limit line in the video are real too.
            print("Warm-up: running the speed test…", flush=True)
            wp.locator(".wifi-speed .btn").click()
            wait_for(wp, "!document.querySelector('.wifi-speed .btn')?.disabled", 120)
            time.sleep(15)
        state = warm.storage_state()
        warm.close()

        ctx = browser.new_context(viewport={"width": W, "height": H}, color_scheme="dark",
                                  storage_state=state, bypass_csp=True,
                                  record_video_dir=str(RAW),
                                  record_video_size={"width": W, "height": H})
        page = ctx.new_page()
        page.goto(BASE + "/")
        page.wait_for_selector("#netview svg")
        page.evaluate("a => { window.__own = a; }", own_addresses(IFACE))
        page.evaluate(OVERLAY_JS)
        page.evaluate(PRIVACY_JS)
        page.evaluate(EXTRA_JS)
        page.mouse.move(960, 540)
        d = Director(page)
        d.at("start")
        title = "<b>Network Traffic Analyzer</b>"
        page.set_default_timeout(8000)   # a missing control should fail fast, not hang

        # Scene 1: overview (0-9s)
        d.caption(f"{title} &nbsp;·&nbsp; live network visibility &amp; threat detection")
        d.sweep([(700, 330), (1200, 400), (960, 540)], 1.0)
        d.pause(1.2)
        d.caption("Python · FastAPI · Scapy · WebSockets &nbsp;—&nbsp; capturing this Mac's "
                  "real traffic, live")
        d.sweep([(1450, 260), (1500, 140)], 1.0)
        d.pause(0.6)
        d.caption(None)

        # Scene 2: visualisation (9-26s)
        d.at("scene 2")
        d.caption("Live isometric map: this Mac, the router and every server it talks to")
        d.move(".node.is-self", 0.9)
        d.pause(0.9)
        d.move('.node[data-key="gw"]', 0.8)
        d.pause(0.8)
        d.hover_public_node(1.0)
        d.pause(1.4)
        d.caption("Flows: who is using your bandwidth, sized by share")
        d.tab("#tab-flows")
        d.pause(1.5)
        d.caption("World: where those servers are (offline Geo-IP, nothing leaves this Mac)")
        d.tab("#tab-world")
        d.pause(1.8)
        d.tab("#tab-map")
        d.caption("Traffic: bandwidth over time, and what kind of traffic it is")
        d.move("#bw-chart", 1.0)
        d.pause(0.5)
        d.move(".protolegend span", 0.9)
        d.pause(1.3)
        d.caption(None)

        # Scene 3: what is this? and its packets (26-48s)
        d.at("scene 3")
        d.caption("Click any server: a plain-English card says who runs it and which app uses it")
        d.hover_public_node(1.0)
        d.pause(0.4)
        page.mouse.down()
        d.pause(0.06)
        page.mouse.up()
        d.pause(3.6)
        d.caption("“Show its packets” opens the packet details, filtered to that server")
        if not d.click(".ipcard .btn-start", 0.9):
            page.keyboard.press("Escape")
        d.pause(1.3)
        if page.locator("#drawer-body").is_hidden():     # never film a closed drawer
            d.click("#drawer-toggle", 0.8)
        d.caption("Pick any packet: it is explained in plain English, then decoded")
        d.click_clean_row(None, 1.0)
        d.pause(2.6)
        d.caption("Quick filters and a query language:  proto == DNS")
        d.type("#filter-input", "proto == DNS")
        d.pause(1.6)
        d.caption("Spot the unencrypted traffic: plain HTTP is one filter away")
        d.type("#filter-input", "proto == HTTP")
        d.pause(0.8)
        d.click_clean_row("HTTP", 1.0)
        d.pause(3.2)
        d.page.fill("#filter-input", "")
        d.click("#drawer-toggle", 0.9)
        d.caption(None)

        # Scene 4: security (46-70s). What it says depends on what was really detected.
        d.at("scene 4")
        found = page.locator("#alerts .alert-row")
        if found.count():
            what = (found.first.locator(".what").text_content() or "an alert").lower()
            if "slow" in what:
                d.caption("When the internet gets slow, an alert says why, and whether "
                          "this Mac is the cause")
            else:
                d.caption(f"Security monitoring: it flagged a real {what} on this network")
            d.move("#alerts", 1.0)
            d.pause(1.0)
            if found.first.locator(".explain").is_hidden():
                d.click("#alerts .alert-row .info-btn", 0.9)
            d.caption("Plain-English details: the numbers, is it this Mac?, what to do")
            d.pause(4.5)
        else:
            d.caption("Security monitoring: nothing suspicious on this network right now")
            d.move("#alerts", 1.0)
            d.pause(2.0)
            d.caption("It watches for port scans, cleartext passwords, ARP spoofing, DNS "
                      "tunnelling, rogue DHCP and VPN leaks")
            d.pause(3.0)
        d.caption("A built-in guide explains every panel, colour and protocol")
        d.click("#btn-help", 0.9)
        d.pause(1.0)
        page.evaluate("() => document.querySelectorAll('.help-sec')[1]?.scrollIntoView("
                      "{behavior:'smooth', block:'start'})")
        d.pause(2.0)
        d.click("#help-close", 0.8)
        d.caption("Wi-Fi tab: signal and latency, turned into one plain answer")
        d.tab("#tab-wifi")
        d.pause(3.5)
        d.caption("A speed test per network (home, campus, café) tells it how full the "
                  "connection is")
        d.move(".wifi-speed", 1.0)
        d.pause(3.5)
        d.click("#tab-map", 0.8)
        d.caption(None)

        # Scene 5: extras (72-82s)
        d.at("scene 5")
        d.caption("Save the session as a .pcap for Wireshark, or open one to analyse")
        d.click("#btn-more", 0.9)
        d.pause(0.9)
        d.click("#btn-export", 0.8)
        d.pause(2.4)
        d.click("#export-cancel", 0.8)
        d.caption("One click switches to the built-in demo (synthetic traffic) and back")
        d.move("#mode-demo", 0.9)
        d.pause(1.8)
        d.caption(None)

        # Scene 6: final (82-90s)
        d.at("scene 6")
        d.sweep([(960, 600), (700, 640)], 0.9)   # parked over empty floor, no hover card
        d.pause(1.2)
        d.caption(f"{title} &nbsp;|&nbsp; Cybersecurity Portfolio Project")
        d.pause(2.6)
        d.at("end")

        leaks = sorted(set(page.evaluate("window.__leaks || []")))
        video = page.video
        ctx.close()
        path = video.path()
        browser.close()
    traffic.stop.set()
    if leaks:
        print("\nPRIVACY AUDIT FAILED. Something identifying was on screen unblurred:")
        for item in leaks[:20]:
            print("  -", item)
        print("No video was written. Fix the masking and record again.")
        return 3
    print("Privacy audit: nothing identifying was on screen unblurred.")
    raw = RAW / "network-traffic-analyzer-raw.webm"
    Path(path).replace(raw)
    to_mp4(raw, FINAL)
    print(f"Saved {FINAL} ({FINAL.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
