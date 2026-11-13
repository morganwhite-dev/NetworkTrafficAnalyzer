"""Take the README screenshots and GIF from a LIVE capture of this Mac.

1. Start a live capture with a known token (needs ChmodBPF or sudo):
       NTA_TOKEN=live-screenshots-0123 scripts/run.sh
2. In another terminal:
       NTA_TOKEN=live-screenshots-0123 .venv/bin/python scripts/capture_screenshots.py

It browses a few public sites in the background so there is always traffic, and runs the
Wi-Fi tab's speed test once (about 20 s and a few hundred MB), which also shows the
"this Mac is filling the connection" alert and the speed-limit line.

Privacy: these are pictures of a real network. The page blurs other devices' names and
addresses, this Mac's own addresses, the router's address, hardware addresses and the hex
dump (the same filter scripts/record_demo.py uses, plus the address card and the Wi-Fi tab).
Internet server names stay visible. Before saving anything it checks every visible piece of
text for another device's name or this Mac's addresses and stops if it finds one. Look at the
pictures before you publish them anyway.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

from PIL import Image
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_demo import PRIVACY_JS, Traffic, own_addresses  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
BASE = os.environ.get("NTA_URL", "http://localhost:8000")
TOKEN = os.environ.get("NTA_TOKEN", "")
SCALE = float(os.environ.get("NTA_SHOT_SCALE", "1.5"))
IFACE = os.environ.get("NTA_IFACE", "en0")
SPEED_TEST = os.environ.get("NTA_SPEED_TEST", "1") != "0"

# Private addresses and hardware addresses, anywhere in a piece of text.
PRIV_SOURCE = (r"(^|[^0-9a-f:])(10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80:"
               r"|[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5})")

# The parts of the dashboard that are newer than the recorder's filter: the address card,
# the Wi-Fi tab, and the labels under This Mac and the router.
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
    const sel = '.ipcard__ip, .ipcard__summary, .ipcard__facts dd, .tile-sub, .wifi-note, '
      + '.verdict, .wifi-help dd, .alert-row .why, .alert-row .explain span, .hc-sub, '
      + '.hovercard div, .prow .info, .insp-body .meta, .chip, #nv-stat';
    for (const el of document.querySelectorAll(sel)) blur(el, risky(el.textContent || ''));
    // A card about another device names it in the title: hide the whole card.
    const card = document.querySelector('.ipcard');
    if (card && !card.hidden) {
      const title = card.querySelector('.ipcard__title')?.textContent || '';
      blur(card, (window.__keys || []).some((k) => k && title.includes(k)));
    }
  };
  setInterval(run, 120);
  run();
})();
""".replace("PRIV_SOURCE", json.dumps(PRIV_SOURCE))


def wait_for(page: Page, js: str, timeout: float = 120) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if page.evaluate(js):
            return True
        time.sleep(0.5)
    return False


def check(page: Page, what: str) -> None:
    """Stop before saving a picture with something private in it."""
    page.wait_for_timeout(450)   # one more pass of both filters
    # Marked is not the same as hidden: make sure the blur really renders.
    weak = page.evaluate("""[...document.querySelectorAll('.pn-blur, #iface-select')]
        .filter((e) => e.getClientRects().length && !getComputedStyle(e).filter.includes('blur'))
        .length""")
    if weak:
        raise SystemExit(f"Not saving {what}: {weak} private item(s) are marked but not blurred.")
    leaks = page.evaluate("(window.__leaks || []).splice(0)")
    if leaks:
        raise SystemExit(f"Not saving {what}: private details are visible:\n  "
                         + "\n  ".join(sorted(set(leaks))[:10]))


def shot(page: Page, selector: str | None, name: str) -> None:
    check(page, name)
    path = OUT / name
    if selector:
        page.locator(selector).first.screenshot(path=str(path))
    else:
        page.screenshot(path=str(path))
    print(f"  {path.relative_to(ROOT)}")


def park(page: Page) -> None:
    page.mouse.move(820, 560)   # over the empty floor of the map: no tooltip, no hover state
    page.wait_for_timeout(300)


def main() -> int:
    if not TOKEN:
        print("Set NTA_TOKEN to the token the live server was started with.")
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    traffic = Traffic()
    traffic.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel="chrome", headless=True)
            # bypass_csp: the dashboard's CSP would block the filter's blur style, leaving
            # everything marked "blurred" but perfectly readable.
            ctx = browser.new_context(viewport={"width": 1600, "height": 1000},
                                      device_scale_factor=SCALE, color_scheme="dark",
                                      bypass_csp=True)
            ctx.add_init_script("try{localStorage.setItem('nta-firstrun-dismissed','1')}"
                                "catch(e){}")
            page = ctx.new_page()
            page.goto(f"{BASE}/?t={TOKEN}")
            page.wait_for_selector("#netview svg")
            page.evaluate(f"window.__own = {own_addresses(IFACE)!r}")
            page.evaluate(PRIVACY_JS)
            page.evaluate(EXTRA_JS)
            if "Start" in page.locator("#btn-capture").inner_text():
                page.click("#btn-capture")
            if not wait_for(page, "document.body.textContent.includes('LIVE')", 20):
                raise SystemExit("Live capture didn't start (permission? see the terminal).")

            print("Collecting traffic and Wi-Fi readings…")
            page.click("#tab-wifi")
            time.sleep(12)
            if SPEED_TEST:
                print("Running the speed test (about 20 s)…")
                page.locator(".wifi-speed .btn").click()
                wait_for(page, "!document.querySelector('.wifi-speed .btn')?.disabled", 120)
                time.sleep(15)       # let the alert settle after the test
            park(page)
            print("Saving screenshots:")
            shot(page, "#panel-network", "netview-wifi.png")

            page.click("#tab-map")
            time.sleep(4)
            row = page.locator(".alert-row").first
            if row.count() and row.locator(".info-btn").count() \
                    and row.locator(".explain").is_hidden():
                row.locator(".info-btn").click()
            park(page)
            shot(page, None, "dashboard.png")
            shot(page, "#panel-network", "netview-map.png")
            shot(page, "#panel-alerts", "alerts.png")
            shot(page, "#panel-traffic", "traffic.png")

            column_label = ".node-label[text-anchor='start'], .node-label:not([text-anchor])"
            server = page.locator(".node[data-key^='h:']").filter(
                has=page.locator(column_label))
            target = server.first if server.count() else page.locator(".node[data-key^='h:']").last
            target.hover()
            time.sleep(0.6)
            shot(page, "#panel-network", "netview-hover.png")
            target.click()
            wait_for(page, "!document.querySelector('.ipcard__summary.is-loading')", 15)
            time.sleep(0.6)
            shot(page, None, "ipcard.png")
            page.keyboard.press("Escape")
            park(page)

            page.click("#tab-flows")
            time.sleep(1.5)
            park(page)
            shot(page, "#panel-network", "netview-flows.png")
            page.click("#tab-world")
            time.sleep(2.5)
            park(page)
            shot(page, "#panel-network", "netview-world.png")
            page.click("#tab-map")
            time.sleep(1)

            page.click("#drawer-toggle")
            time.sleep(1.2)
            page.locator(".prow").nth(4).click()
            time.sleep(1)
            page.mouse.move(800, 120)
            shot(page, None, "drawer.png")
            shot(page, "#drawer-body", "inspector.png")
            page.click("#drawer-toggle")
            park(page)

            print("Recording the map GIF…")
            frames = []
            panel = page.locator("#panel-network")
            for _ in range(28):
                check(page, "demo.gif")
                frames.append(Image.open(io.BytesIO(panel.screenshot(scale="css"))).convert("RGB"))
                time.sleep(0.12)
            width = 960
            frames = [f.resize((width, int(f.height * width / f.width)), Image.LANCZOS)
                      for f in frames]
            pal = frames[0].quantize(colors=128, method=Image.Quantize.MEDIANCUT)
            frames_p = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
            gif = OUT / "demo.gif"
            frames_p[0].save(gif, save_all=True, append_images=frames_p[1:], duration=140,
                             loop=0, optimize=True)
            print(f"  {gif.relative_to(ROOT)} ({gif.stat().st_size // 1024} KB)")
            browser.close()
    finally:
        traffic.stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
