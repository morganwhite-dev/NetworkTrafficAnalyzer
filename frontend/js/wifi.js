// Wi-Fi tab: one plain-language verdict, three numbers, and how they moved.

import { el } from "./format.js";

const LEVEL_TEXT = {
  good: "LOOKS GOOD",
  warn: "WORTH A LOOK",
  bad: "FOUND THE PROBLEM",
  info: "CHECKING",
};
const BARS = { strong: 4, good: 3, fair: 2, weak: 1, unknown: 0 };

function ms(v) {
  if (v === null || v === undefined) return "—";
  return v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
}

function pct(v) {
  return `${Math.round((v || 0) * 100)}% lost`;
}

// Keep "Wi-Fi" on one line (U+2011 is a non-breaking hyphen).
const nb = (s) => String(s ?? "").replaceAll("Wi-Fi", "Wi\u2011Fi");

export class WifiView {
  constructor({ root, stat }) {
    this.root = root;
    this.stat = stat;
    this.charts = null;
    this.build();
  }

  build() {
    this.verdict = el("div", { class: "verdict lvl-info hud-notch" });
    this.linkRow = el("div", { class: "wifi-link" });
    this.note = el("div", { class: "wifi-note" });
    this.tiles = {
      signal: this.tile("Signal"),
      router: this.tile("Router"),
      internet: this.tile("Internet"),
    };
    this.signalCanvas = el("canvas");
    this.latencyCanvas = el("canvas");
    const help = el("dl", { class: "wifi-help" },
      el("dt", { text: "Signal" }), el("dd", { text: "above −67 dBm is fine. Weaker means move closer or add a mesh node." }),
      el("dt", { text: "Router" }), el("dd", { text: "under 15 ms is fine. Slow or spiky here = a Wi-Fi problem in your home." }),
      el("dt", { text: "Internet" }), el("dd", { text: "slow here while the router is fast = your modem or provider." }));
    const left = el("div", { class: "wifi-left" }, this.verdict, this.linkRow, this.note, help);
    const right = el(
      "div",
      { class: "wifi-right" },
      el(
        "div",
        { class: "wifi-tiles" },
        this.tiles.signal.box,
        this.tiles.router.box,
        this.tiles.internet.box,
      ),
      el(
        "div",
        { class: "wifi-chart-label" },
        el("span", { text: "SIGNAL · dBm" }),
        el("span", { class: "muted", text: "higher is better" }),
      ),
      el("div", { class: "wifi-chart" }, this.signalCanvas),
      el(
        "div",
        { class: "wifi-chart-label" },
        el("span", { text: "RESPONSE TIME · ms" }),
        el(
          "span",
          {},
          el("span", { class: "t-hi", text: "router" }),
          el("span", { class: "muted", text: " · " }),
          el("span", { class: "t-data", text: "internet" }),
          el("span", { class: "muted", text: " · " }),
          el("span", { class: "t-alert", text: "lost" }),
        ),
      ),
      el("div", { class: "wifi-chart" }, this.latencyCanvas),
    );
    this.root.replaceChildren(el("div", { class: "wifi" }, left, right));
  }

  tile(label) {
    const value = el("div", { class: "tile-value", text: "—" });
    const sub = el("div", { class: "tile-sub", text: "" });
    const bars =
      label === "Signal"
        ? el(
            "div",
            { class: "bars", "aria-hidden": "true" },
            ...[1, 2, 3, 4].map((i) => el("span", { class: `b${i}` })),
          )
        : null;
    const box = el(
      "div",
      { class: "tile" },
      el(
        "div",
        { class: "tile-label" },
        el("span", { text: label.toUpperCase() }),
        bars,
      ),
      value,
      sub,
    );
    return { box, value, sub, bars };
  }

  ensureCharts() {
    if (this.charts || !window.Chart) return;
    const common = {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        x: {
          type: "linear",
          grid: { display: false },
          border: { display: false },
          ticks: { maxTicksLimit: 5, callback: (v) => this.xLabel(v) },
        },
      },
    };
    this.charts = {
      signal: new window.Chart(this.signalCanvas, {
        type: "line",
        data: {
          datasets: [
            {
              data: [],
              borderColor: "#00f3ff",
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.3,
            },
            {
              data: [],
              borderColor: "rgba(255,176,0,.45)",
              borderWidth: 1,
              borderDash: [3, 4],
              pointRadius: 0,
            },
            {
              data: [],
              borderColor: "rgba(255,0,60,.45)",
              borderWidth: 1,
              borderDash: [3, 4],
              pointRadius: 0,
            },
          ],
        },
        options: {
          ...common,
          scales: {
            ...common.scales,
            y: {
              suggestedMin: -90,
              suggestedMax: -40,
              border: { display: false },
              ticks: { maxTicksLimit: 4 },
            },
          },
          plugins: {
            ...common.plugins,
            tooltip: {
              callbacks: {
                label: (i) =>
                  i.datasetIndex === 0 ? `${i.parsed.y} dBm` : null,
              },
            },
          },
        },
      }),
      latency: new window.Chart(this.latencyCanvas, {
        type: "line",
        data: {
          datasets: [
            {
              data: [],
              borderColor: "#00f3ff",
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.25,
              spanGaps: false,
            },
            {
              data: [],
              borderColor: "#00ff41",
              borderWidth: 1.5,
              pointRadius: 0,
              tension: 0.25,
              spanGaps: false,
            },
            {
              data: [],
              type: "scatter",
              backgroundColor: "#ff003c",
              pointRadius: 2.5,
              pointStyle: "rectRot",
            },
          ],
        },
        options: {
          ...common,
          scales: {
            ...common.scales,
            y: {
              beginAtZero: true,
              border: { display: false },
              ticks: { maxTicksLimit: 4 },
            },
          },
          plugins: {
            ...common.plugins,
            tooltip: {
              callbacks: {
                label: (i) =>
                  i.datasetIndex === 2
                    ? "lost"
                    : `${Math.round(i.parsed.y)} ms`,
              },
            },
          },
        },
      }),
    };
  }

  xLabel(v) {
    const d = Math.round(v - (this.lastT || v));
    return d === 0 ? "now" : `${d}s`;
  }

  update(msg) {
    if (!msg) return;
    this.ensureCharts();
    const v = msg.verdict || {};
    const s = v.stats || {};
    const level = v.level || "info";

    // Verdict card
    this.verdict.className = `verdict lvl-${level}${level === "info" ? "" : " hud-notch"}`;
    const kids = [
      el("div", { class: "v-k", text: LEVEL_TEXT[level] || "CHECKING" }),
      el("div", { class: "v-title", text: nb(v.title || "Checking your Wi-Fi…") }),
    ];
    if (v.detail) kids.push(el("p", { class: "v-detail", text: nb(v.detail) }));
    if (v.tips?.length)
      kids.push(
        el(
          "ul",
          { class: "v-tips" },
          ...v.tips.map((t) => el("li", { text: nb(t) })),
        ),
      );
    this.verdict.replaceChildren(...kids);

    // Link details
    const l = msg.link || {};
    const chips = [];
    if (msg.demo)
      chips.push(el("span", { class: "chip warn", text: "DEMO READINGS" }));
    if (l.connected) {
      for (const c of [
        l.band,
        l.channel && `CH ${l.channel}`,
        l.width,
        l.phy,
        l.tx_rate && `${Math.round(l.tx_rate)} Mbps link`,
      ]) {
        if (c)
          chips.push(
            el("span", { class: "chip", text: String(c).toUpperCase() }),
          );
      }
    } else if (!msg.signal_source) {
      chips.push(
        el("span", {
          class: "chip",
          text: "NO SIGNAL READINGS ON THIS SYSTEM",
        }),
      );
    }
    this.linkRow.replaceChildren(...chips);
    this.note.textContent =
      msg.active || msg.demo
        ? `Pinging your router${msg.router ? ` (${msg.router})` : ""} and ${msg.target} every 2 s while this tab is open, and every 5 s during a live capture so you get an alert when it's slow.`
        : "Starting the check…";

    // Tiles
    const q = s.quality || "unknown";
    this.tiles.signal.value.textContent =
      s.rssi != null ? `${Math.round(s.rssi)} dBm` : "—";
    this.tiles.signal.sub.textContent =
      s.snr != null ? `${q} · ${Math.round(s.snr)} dB above noise` : q;
    this.tiles.signal.box.className = `tile q-${q}`;
    const n = BARS[q] ?? 0;
    this.tiles.signal.bars
      ?.querySelectorAll("span")
      .forEach((b, i) => b.classList.toggle("on", i < n));
    this.tiles.router.value.textContent = ms(s.gw_ms);
    this.tiles.router.sub.textContent = msg.router
      ? `${pct(s.gw_loss)} · ${msg.router}`
      : "router address unknown";
    this.tiles.router.box.className = `tile${s.gw_loss >= 0.05 || s.gw_ms >= 40 ? " is-bad" : s.gw_ms >= 15 ? " is-warn" : ""}`;
    this.tiles.internet.value.textContent = ms(s.net_ms);
    this.tiles.internet.sub.textContent = `${pct(s.net_loss)} · ${msg.target}`;
    const beyond =
      s.net_ms != null && s.gw_ms != null ? s.net_ms - s.gw_ms : s.net_ms;
    this.tiles.internet.box.className = `tile${s.net_loss >= 0.03 || beyond >= 120 ? " is-bad" : beyond >= 60 ? " is-warn" : ""}`;

    // Charts
    const samples = msg.samples || [];
    this.lastT = samples.length ? samples[samples.length - 1].t : 0;
    if (this.charts) {
      const sig = samples
        .filter((x) => x.rssi != null)
        .map((x) => ({ x: x.t, y: x.rssi }));
      const span = sig.length ? [sig[0].x, sig[sig.length - 1].x] : [0, 0];
      const c1 = this.charts.signal.data.datasets;
      c1[0].data = sig;
      c1[1].data = [
        { x: span[0], y: -67 },
        { x: span[1], y: -67 },
      ];
      c1[2].data = [
        { x: span[0], y: -75 },
        { x: span[1], y: -75 },
      ];
      const t0 = samples.length ? samples[0].t : 0;
      for (const ch of [this.charts.signal, this.charts.latency]) {
        ch.options.scales.x.min = t0;
        ch.options.scales.x.max = this.lastT;
      }
      this.charts.signal.update("none");
      const pinged = samples.filter((x) => x.pinged);
      const c2 = this.charts.latency.data.datasets;
      c2[0].data = pinged.map((x) => ({ x: x.t, y: x.gw ?? null }));
      c2[1].data = pinged.map((x) => ({ x: x.t, y: x.net ?? null }));
      const top = Math.max(
        10,
        ...pinged.flatMap((x) => [x.gw || 0, x.net || 0]),
      );
      c2[2].data = pinged
        .filter((x) => x.gw == null || x.net == null)
        .map((x) => ({ x: x.t, y: top }));
      this.charts.latency.update("none");
    }

    // Panel header
    const parts = [];
    if (l.band)
      parts.push(
        el("span", { text: l.band.toUpperCase() }),
        el("span", { class: "dot", text: "·" }),
      );
    if (s.rssi != null)
      parts.push(
        el("span", { text: `${Math.round(s.rssi)} dBm` }),
        el("span", { class: "dot", text: "·" }),
      );
    parts.push(
      el("span", {
        class: level === "bad" ? "t-alert" : level === "warn" ? "t-warn" : "",
        text: (v.title || "").toUpperCase(),
      }),
    );
    this.stat.replaceChildren(...parts);
  }

  resize() {
    if (this.charts) {
      this.charts.signal.resize();
      this.charts.latency.resize();
    }
  }
}
