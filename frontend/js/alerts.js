// Alerts feed: newest first, severity bar, click to focus the host.

import { post } from "./api.js";
import { clock, el, icon } from "./format.js";

const RED = new Set(["high", "critical"]);

export class AlertsFeed {
  constructor({ root, stat, onFocus }) {
    this.root = root;
    this.stat = stat;
    this.onFocus = onFocus;
    this.items = [];
    this.render();
  }

  reset(alerts) {
    this.items = alerts.slice(-200).reverse();
    this.render();
  }

  add(alert) {
    this.items.unshift(alert);
    if (this.items.length > 200) this.items.length = 200;
    this.root.prepend(this.row(alert));
    const extra = this.root.querySelectorAll(".alert-row");
    if (extra.length > 200) extra[extra.length - 1].remove();
    this.root.querySelector(".empty")?.remove();
    this.updateStat();
  }

  update(alert) {
    const i = this.items.findIndex((a) => a.id === alert.id);
    if (i === -1) return;
    this.items[i] = alert;
    const old = this.root.querySelector(`.alert-row[data-id="${alert.id}"]`);
    if (old) old.replaceWith(this.row(alert, false));
  }

  updateStat() {
    const red = this.items.filter((a) => RED.has(a.severity)).length;
    this.stat.replaceChildren();
    if (red)
      this.stat.append(
        el("span", { class: "t-alert", text: `${red} HIGH` }),
        el("span", { class: "dot", text: "·" }),
      );
    this.stat.append(el("span", { text: `${this.items.length} TOTAL` }));
  }

  render() {
    if (!this.items.length) {
      this.root.replaceChildren(
        el("div", {
          class: "empty",
          text: "No alerts yet. Port scans, cleartext passwords, bandwidth hogs and spoofing show up here.",
        }),
      );
    } else {
      this.root.replaceChildren(...this.items.map((a) => this.row(a)));
    }
    this.updateStat();
  }

  row(a, animate = true) {
    const sevCls = RED.has(a.severity)
      ? "sev-r"
      : a.severity === "medium"
        ? "sev-a"
        : "";
    const body = el(
      "div",
      { class: "body" },
      el(
        "div",
        { class: "top" },
        el("span", {
          class: `sev sev-${a.severity}`,
          text: a.severity.toUpperCase(),
        }),
        el("span", { class: "what", text: a.title }),
        el("span", { class: "time", text: clock(a.ts) }),
      ),
      el("div", { class: "why", text: a.reason, title: a.reason }),
    );
    if (a.has_secret) {
      const btn = el(
        "button",
        { class: "link-btn", type: "button" },
        icon("eye"),
        el("span", { text: "Reveal" }),
      );
      const out = el("span", { class: "secret-text" });
      btn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (out.textContent) {
          out.textContent = "";
          btn.lastChild.textContent = "Reveal";
          return;
        }
        try {
          const r = await post(`/api/alerts/${a.id}/reveal`);
          out.textContent = ` ${r.secret}`;
          btn.lastChild.textContent = "Hide";
        } catch (err) {
          out.textContent = ` ${err.message}`;
        }
      });
      body.append(el("div", { class: "reveal" }, btn, out));
    }
    const row = el(
      "div",
      {
        class: `alert-row ${sevCls}${animate ? "" : " no-anim"}`,
        "data-id": a.id,
        role: "button",
        tabindex: "0",
        title: "Show this host",
      },
      el("div", { class: "bar" }),
      body,
    );
    const focus = () => a.hosts?.[0] && this.onFocus(a.hosts[0], a);
    row.addEventListener("click", focus);
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") focus();
    });
    return row;
  }
}
