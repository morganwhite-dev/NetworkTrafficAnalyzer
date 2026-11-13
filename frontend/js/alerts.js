// Alerts feed: newest first, severity bar, click to focus the host.

import { post } from "./api.js";
import { clock, el, icon } from "./format.js";
import { alertInfo, alertNumbers, SEVERITY_TIPS } from "./glossary.js";

const RED = new Set(["high", "critical"]);

export class AlertsFeed {
  constructor({ root, stat, onFocus, labelFor }) {
    this.root = root;
    this.stat = stat;
    this.onFocus = onFocus;
    this.labelFor = labelFor || ((ip) => ip);
    this.auto = null; // the alert we opened ourselves: the next serious one replaces it
    this.items = [];
    this.open = new Set(); // alert ids whose explanation is expanded: survives in-place updates
    this.render();
  }

  reset(alerts) {
    this.items = alerts.slice(-200).reverse();
    this.render();
  }

  add(alert) {
    // A new serious alert opens its own details (the numbers and what to do), and closes the
    // previous one we opened, so the panel never fills up with expanded rows.
    if (RED.has(alert.severity)) {
      const prevId = this.auto;
      if (prevId !== null) {
        this.open.delete(prevId);
        const prev = this.items.find((a) => a.id === prevId);
        const old = this.root.querySelector(`.alert-row[data-id="${prevId}"]`);
        if (old && prev) old.replaceWith(this.row(prev, false));
      }
      this.open.add(alert.id);
      this.auto = alert.id;
    }
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
            el("li", { text: "slow Wi-Fi or a slow internet connection, and whether this Mac is the cause" }),
            el("li", { text: "this Mac or one server using a lot of bandwidth" }),
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
    const sevCls = a.ended
      ? "is-ended"
      : RED.has(a.severity)
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
        a.ended
          ? el("span", {
              class: "ended",
              text: "ENDED",
              "data-tip": `Stopped at ${clock(a.ended)}. The numbers are from when it was happening.`,
            })
          : null,
        el("span", { class: "time", text: clock(a.ts) }),
      ),
      el("div", { class: "why", text: a.reason, title: a.reason }),
    );
    const info = alertInfo(a.kind);
    const numbers = alertNumbers(a, this.labelFor);
    if (info) {
      const explain = el(
        "div",
        { class: "explain", hidden: !this.open.has(a.id) },
        numbers.length
          ? el(
              "div",
              { class: "nums" },
              ...numbers.map((n) =>
                el(
                  "div",
                  { class: n.red ? "red" : "" },
                  el("b", { text: n.value }),
                  el("span", { text: n.label }),
                ),
              ),
            )
          : null,
        a.detail?.why ? el("b", { text: "Is it this Mac?" }) : null,
        a.detail?.why ? el("span", { text: a.detail.why }) : null,
        el("b", { text: "What it means" }),
        el("span", { text: a.detail?.summary || info.means }),
        el("b", { text: "What to do" }),
        a.detail?.tips?.length
          ? el("ul", { class: "tips" }, ...a.detail.tips.map((t) => el("li", { text: t })))
          : el("span", { text: info.todo }),
      );
      const btn = el("button", {
        class: "info-btn",
        type: "button",
        "aria-expanded": String(this.open.has(a.id)),
        "aria-label": `What does ${a.title} mean?`,
        "data-tip": "Details: the numbers, what it means and what to do",
        text: "?",
      });
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const open = explain.hidden;
        explain.hidden = !open;
        if (open) this.open.add(a.id);
        else this.open.delete(a.id);
        if (this.auto === a.id) this.auto = null; // you took over: leave it as you set it
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
