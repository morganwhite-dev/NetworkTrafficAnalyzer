"""Capture the README screenshots and demo GIF from a running demo server.

1. Start the demo (replay only, so no real traffic ends up in the images, and
   synthetic Wi-Fi readings so your real network details stay out too):
       NTA_TOKEN=shots NTA_WIFI_DEMO=1 scripts/run.sh --replay samples/demo.pcap --loop
2. In another terminal:
       NTA_TOKEN=shots .venv/bin/python scripts/capture_screenshots.py

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
        page = ctx.new_page()
        page.goto(f"{BASE}/?t={TOKEN}")
        page.wait_for_selector("#netview svg")
        print("Waiting for the demo's incidents (bandwidth hog, port scan, cleartext login)…")
        wait_for(page, "document.querySelector('#nv-stat')?.textContent.includes('3 FLAGGED')")
        wait_for(page, "[...document.querySelectorAll('.incident .ttl')]"
                       ".some(e => e.textContent.includes('HOG'))"
                       " || document.querySelectorAll('.alert-row').length >= 4")
        time.sleep(2.5)

        # Show the hog first in the incident card.
        for _ in range(4):
            if "HOG" in (page.locator(".incident .ttl").first.text_content() or ""):
                break
            page.locator(".incident [data-next]").first.click()
            time.sleep(0.3)

        print("Saving screenshots:")
        shot(page, None, "dashboard.png")
        page.screenshot(path=str(OUT / "dashboard-full.png"), full_page=True)
        print("  docs/screenshots/dashboard-full.png")
        shot(page, "#panel-network", "netview-map.png")

        hog = page.locator(".node.is-high[data-key^='h:5.']").first
        if hog.count():
            hog.hover()
            time.sleep(0.4)
            shot(page, "#panel-network", "netview-hover.png")
            page.mouse.move(5, 5)

        page.click("#tab-flows")
        time.sleep(1.2)
        shot(page, "#panel-network", "netview-flows.png")
        page.click("#tab-wifi")
        print("  (collecting Wi-Fi demo readings…)")
        time.sleep(24)
        shot(page, "#panel-network", "netview-wifi.png")
        page.click("#tab-map")
        time.sleep(0.5)

        shot(page, "#alerts", "alerts.png")
        shot(page, "section[aria-label='Charts']", "charts-geo.png")

        page.fill("#filter-input", "ip == 192.168.1.77 and proto == TCP")
        time.sleep(0.6)
        shot(page, "section[aria-label='Packets']", "filter.png")

        page.fill("#filter-input", "proto == HTTP and info contains POST")
        time.sleep(0.6)
        page.locator(".prow").first.click()
        time.sleep(0.8)
        shot(page, "section[aria-label='Packets']", "inspector.png")
        page.fill("#filter-input", "")

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
