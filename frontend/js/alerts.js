// Alerts feed: newest first, severity bar, click to focus the host.

import { post } from "./api.js";
import { clock, el, icon } from "./format.js";
import { alertInfo, SEVERITY_TIPS } from "./glossary.js";

const RED = new Set(["high", "critical"]);

export class AlertsFeed {
  constructor({ root, stat, onFocus }) {
    this.root = root;
    this.stat = stat;
    this.onFocus = onFocus;
    this.items = [];
    this.open = new Set(); // alert ids whose explanation is expanded: survives in-place updates
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
    const count = (sev) => this.items.filter((a) => a.severity === sev).length;
    this.stat.replaceChildren();
    for (const [sev, label] of [
      ["critical", "CRITICAL"],
      ["high", "HIGH"],
    ]) {
      const n = count(sev);
      if (n)
        this.stat.append(
          el("span", { class: "t-alert", text: `${n} ${label}` }),
          el("span", { class: "dot", text: "·" }),
        );
    }
    this.stat.append(el("span", { text: `${this.items.length} TOTAL` }));
  }

  render() {
    if (!this.items.length) {
      this.root.replaceChildren(
        el(
          "div",
          { class: "allclear empty" },
          el("span", { class: "ok", text: "ALL CLEAR" }),
          el("span", { text: "Nothing suspicious so far. Watching for:" }),
          el(
            "ul",
            {},
            el("li", { text: "devices scanning your network for open doors" }),
            el("li", { text: "passwords or logins sent without encryption" }),
            el("li", { text: "one server hogging your bandwidth" }),
            el("li", { text: "devices pretending to be your router" }),
            el("li", { text: "data hidden inside name lookups, and VPN leaks" }),
          ),
        ),
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
          "data-tip": SEVERITY_TIPS[a.severity] || "",
        }),
        el("span", { class: "what", text: a.title }),
        el("span", { class: "time", text: clock(a.ts) }),
      ),
      el("div", { class: "why", text: a.reason, title: a.reason }),
    );
    const info = alertInfo(a.kind);
    if (info) {
      const explain = el(
        "div",
        { class: "explain", hidden: !this.open.has(a.id) },
        el("b", { text: "What it means" }),
        el("span", { text: info.means }),
        el("b", { text: "What to do" }),
        el("span", { text: info.todo }),
      );
      const btn = el("button", {
        class: "info-btn",
        type: "button",
        "aria-expanded": String(this.open.has(a.id)),
        "aria-label": `What does ${a.title} mean?`,
        "data-tip": "What does this mean?",
        text: "?",
      });
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const open = explain.hidden;
        explain.hidden = !open;
        if (open) this.open.add(a.id);
        else this.open.delete(a.id);
        btn.setAttribute("aria-expanded", String(open));
      });
      btn.addEventListener("keydown", (ev) => ev.stopPropagation());
      body.querySelector(".top").insertBefore(btn, body.querySelector(".time"));
      body.append(explain);
    }
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
