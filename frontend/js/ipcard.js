// The "what is this?" card. Click an address anywhere (a device or server on the map, a ribbon,
// a dot on the World tab, an alert, an address in the packet table) and this card opens next to
// it: who it is, in a sentence, plus the facts behind it. The text comes from /api/ip/<address>.
// Everything is put on the page with textContent, never innerHTML.

import { get } from "./api.js";
import { el } from "./format.js";

const WIDTH = 380;

export class IpCard {
  constructor({ onShowPackets, onClose, onOpenChange }) {
    this.onOpenChange = onOpenChange;
    this.onShowPackets = onShowPackets;
    this.onClose = onClose;
    this.ip = null;
    this.token = 0; // answers to a click we have since replaced are ignored
    this.opening = false;
    this.last = { x: 200, y: 200 };
    this.root = el("aside", {
      class: "ipcard",
      role: "dialog",
      "aria-label": "About this address",
      hidden: true,
    });
    document.body.append(this.root);
    // Remember where the pointer last went down, so the card can open beside it.
    document.addEventListener(
      "click",
      (ev) => {
        this.last = { x: ev.clientX, y: ev.clientY };
      },
      true,
    );
    document.addEventListener("click", (ev) => {
      if (this.opening || this.root.hidden) return;
      if (!ev.target.closest(".ipcard")) this.hide(true);
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && !this.root.hidden) this.hide(true);
    });
  }

  hide(notify = false) {
    if (this.root.hidden) return;
    this.root.hidden = true;
    this.ip = null;
    this.token++;
    this.onOpenChange?.(false);
    if (notify) this.onClose?.();
  }

  async show(ip) {
    if (!ip) return this.hide();
    this.ip = ip;
    const mine = ++this.token;
    // The click that opened us is still travelling up the page: don't let it close us.
    this.opening = true;
    setTimeout(() => {
      this.opening = false;
    }, 0);
    this.render({ title: ip, summary: "Looking it up…", facts: [], loading: true });
    this.place();
    try {
      const data = await get(`/api/ip/${encodeURIComponent(ip)}`);
      if (mine !== this.token) return;
      this.render(data);
    } catch (err) {
      if (mine !== this.token) return;
      this.render({
        title: ip,
        summary: `Couldn't look that up: ${err.message}`,
        facts: [],
      });
    }
    this.place();
  }

  render(d) {
    const close = el("button", {
      class: "ipcard__x",
      type: "button",
      "aria-label": "Close",
      text: "×",
    });
    close.addEventListener("click", () => this.hide(true));
    const facts = el("dl", { class: "ipcard__facts" });
    for (const f of d.facts || []) {
      facts.append(el("dt", { text: f.label }), el("dd", { text: f.value }));
    }
    const copy = el("button", { class: "btn", type: "button", text: "Copy address" });
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(d.ip || this.ip);
        copy.textContent = "Copied";
      } catch {
        copy.textContent = "Select it above";
      }
    });
    const show = el("button", {
      class: "btn btn-start",
      type: "button",
      text: "Show its packets",
    });
    show.addEventListener("click", () => this.onShowPackets?.(this.ip));
    this.root.replaceChildren(
      el(
        "header",
        { class: "ipcard__head" },
        el("div", {},
          el("div", { class: "ipcard__title", text: d.title || this.ip }),
          el("div", { class: "ipcard__ip", text: this.ip }),
        ),
        close,
      ),
      el("p", { class: `ipcard__summary${d.loading ? " is-loading" : ""}`, text: d.summary }),
      d.facts?.length ? facts : null,
      d.loading ? null : el("div", { class: "ipcard__actions" }, show, copy),
    );
    this.root.hidden = false;
    this.onOpenChange?.(true);
  }

  /** Beside the pointer, kept on screen and clear of the packet drawer. */
  place() {
    const drawer = document.getElementById("panel-packets");
    const floor = drawer ? drawer.getBoundingClientRect().top : window.innerHeight;
    const h = this.root.offsetHeight;
    let x = this.last.x + 18;
    if (x + WIDTH > window.innerWidth - 12) x = this.last.x - WIDTH - 18;
    x = Math.max(12, Math.min(x, window.innerWidth - WIDTH - 12));
    let y = this.last.y - 24;
    y = Math.min(y, floor - h - 12);
    y = Math.max(64, y);
    this.root.style.left = `${Math.round(x)}px`;
    this.root.style.top = `${Math.round(y)}px`;
  }
}
