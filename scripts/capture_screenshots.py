"""Capture the README screenshots and demo GIF from a running demo server.

1. Start the demo (replay only, so no real traffic ends up in the images, and
   synthetic Wi-Fi readings so your real network details stay out too):
       NTA_TOKEN=demo-screenshots-0123 NTA_WIFI_DEMO=1 \
         scripts/run.sh --replay samples/demo.pcap --loop
2. In another terminal:
       NTA_TOKEN=demo-screenshots-0123 .venv/bin/python scripts/capture_screenshots.py

Uses your installed Google Chrome through Playwright (no browser download).
"""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

from PIL import Image
from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
BASE = os.environ.get("NTA_URL", "http://localhost:8000")
TOKEN = os.environ.get("NTA_TOKEN", "")
SCALE = float(os.environ.get("NTA_SHOT_SCALE", "1.5"))


def wait_for(page: Page, predicate_js: str, timeout: float = 150) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if page.evaluate(predicate_js):
            return
        time.sleep(0.5)
    raise TimeoutError(f"Timed out waiting for: {predicate_js}")


def shot(page: Page, selector: str | None, name: str) -> None:
    path = OUT / name
    if selector:
        page.locator(selector).first.screenshot(path=str(path))
    else:
        page.screenshot(path=str(path))
    print(f"  {path.relative_to(ROOT)}")


def main() -> int:
    if not TOKEN:
        print("Set NTA_TOKEN to the token the demo server was started with.")
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        ctx = browser.new_context(viewport={"width": 1600, "height": 1000},
                                  device_scale_factor=SCALE, color_scheme="dark")
        # The first-run hint is for people, not for the README pictures.
        ctx.add_init_script("try{localStorage.setItem('nta-firstrun-dismissed','1')}catch(e){}")
        page = ctx.new_page()
        page.goto(f"{BASE}/?t={TOKEN}")
        page.wait_for_selector("#netview svg")
        print("Waiting for the demo's incidents (bandwidth hog, port scan, cleartext login)…")
        wait_for(page, "document.querySelector('#nv-stat')?.textContent.includes('3 FLAGGED')")
        wait_for(page, "document.querySelectorAll('.alert-row').length >= 4")
        time.sleep(2.5)

        # Show the hog's details (its numbers, what it means, what to do) in the alert list.
        hog_row = page.locator(".alert-row", has_text="Bandwidth hog").first
        if hog_row.locator(".explain").is_hidden():
            hog_row.locator(".info-btn").click()
        page.mouse.move(800, 900)   # park the pointer so no tooltip or hover state is captured
        time.sleep(0.6)

        print("Saving screenshots:")
        shot(page, None, "dashboard.png")
        shot(page, "#panel-network", "netview-map.png")

        hog = page.locator(".node.is-high[data-key^='h:5.']").first
        if hog.count():
            hog.hover()
            time.sleep(0.4)
            shot(page, "#panel-network", "netview-hover.png")
            page.mouse.move(800, 900)

        page.click("#tab-flows")
        page.mouse.move(800, 900)
        time.sleep(1.2)
        shot(page, "#panel-network", "netview-flows.png")
        page.click("#tab-world")
        page.mouse.move(800, 900)   # off the tab, so its tooltip isn't in the picture
        time.sleep(2.0)
        shot(page, "#panel-network", "netview-world.png")
        page.click("#tab-wifi")
        print("  (collecting Wi-Fi demo readings…)")
        time.sleep(24)
        shot(page, "#panel-network", "netview-wifi.png")
        page.click("#tab-map")
        time.sleep(0.5)
        page.mouse.move(800, 900)

        shot(page, "#panel-alerts", "alerts.png")
        shot(page, "#panel-traffic", "traffic.png")

        # The packet drawer opens by itself when you pick something; here we open it by hand.
        page.click("#drawer-toggle")
        page.fill("#filter-input", "ip == 192.168.1.77 and proto == TCP")
        time.sleep(0.6)
        shot(page, "#drawer-body", "filter.png")

        page.fill("#filter-input", "proto == HTTP and info contains POST")
        time.sleep(0.6)
        page.locator(".prow").first.click()
        time.sleep(0.8)
        shot(page, "#drawer-body", "inspector.png")
        page.mouse.move(800, 100)
        shot(page, None, "drawer.png")
        page.fill("#filter-input", "")
        page.click("#drawer-toggle")

        print("Recording the demo GIF…")
        frames = []
        panel = page.locator("#panel-network")
        for _ in range(28):
            png = panel.screenshot(scale="css")
            frames.append(Image.open(io.BytesIO(png)).convert("RGB"))
            time.sleep(0.12)
        width = 960
        frames = [f.resize((width, int(f.height * width / f.width)), Image.LANCZOS) for f in frames]
        pal = frames[0].quantize(colors=128, method=Image.Quantize.MEDIANCUT)
        frames_p = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
        gif = OUT / "demo.gif"
        frames_p[0].save(gif, save_all=True, append_images=frames_p[1:], duration=140, loop=0,
                         optimize=True)
        print(f"  {gif.relative_to(ROOT)} ({gif.stat().st_size // 1024} KB)")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
