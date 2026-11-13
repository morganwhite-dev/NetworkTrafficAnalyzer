// Bandwidth line chart (Chart.js, vendored) and the protocol share bar.

import { el, fmtCount, fmtPct, fmtRate } from "./format.js";
import { protoTip } from "./glossary.js";

export const PROTO_COLORS = {
  TLS: "#00ff41",
  TCP: "#00b52e",
  QUIC: "#7dffa0",
  UDP: "#00f3ff",
  DNS: "#0096a0",
  HTTP: "#ffb000",
  ICMP: "#8a93a3",
  ARP: "#6b7587",
  Other: "#283040",
};
const ORDER = [
  "TLS",
  "QUIC",
  "TCP",
  "UDP",
  "DNS",
  "HTTP",
  "ICMP",
  "ARP",
  "Other",
];

function setupDefaults() {
  const C = window.Chart;
  Object.assign(C.defaults, {
    color: "#7b8494",
    borderColor: "rgba(255,255,255,.04)",
    animation: false,
  });
  C.defaults.font = { family: '"JetBrains Mono", monospace', size: 10 };
  C.defaults.plugins.legend.display = false;
  Object.assign(C.defaults.plugins.tooltip, {
    backgroundColor: "#0a0a0c",
    borderColor: "#232a36",
    borderWidth: 1,
    cornerRadius: 2,
    padding: 8,
    displayColors: false,
    titleColor: "#8a93a3",
    bodyColor: "#d7dde8",
  });
}

export class Charts {
  constructor({ bwCanvas, bwStat, protoBar, protoLegend, protoTotal }) {
    setupDefaults();
    this.bwStat = bwStat;
    this.protoBar = protoBar;
    this.protoLegend = protoLegend;
    this.protoTotal = protoTotal;
    this.protoNodes = new Map(); // protocol -> { seg, leg, text } reused between updates
    this.protoKey = "";
    this.spikeSet = new Set();
    this.fileMode = false;
    const greenFill = ({ chart }) => {
      const a = chart.chartArea;
      if (!a) return "rgba(0,255,65,.1)";
      const g = chart.ctx.createLinearGradient(0, a.top, 0, a.bottom);
      g.addColorStop(0, "rgba(0,255,65,.22)");
      g.addColorStop(1, "rgba(0,255,65,0)");
      return g;
    };
    this.bw = new window.Chart(bwCanvas, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            data: [],
            borderColor: "#00ff41",
            borderWidth: 1.5,
            pointRadius: 0,
            tension: 0.25,
            fill: "start",
            backgroundColor: greenFill,
            segment: {
              borderColor: (s) =>
                this.spikeSet.has(s.p1DataIndex) ? "#ff003c" : undefined,
            },
          },
          {
            // This network's measured speed (from the Wi-Fi tab's speed test).
            data: [],
            borderColor: "rgba(0,243,255,.55)",
            borderWidth: 1,
            borderDash: [4, 4],
            pointRadius: 0,
            fill: false,
            hidden: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            grid: { display: false },
            border: { display: false },
            ticks: {
              maxTicksLimit: 4,
              maxRotation: 0,
              callback: (v, i) => this.xLabel(i),
            },
          },
          y: {
            border: { display: false },
            beginAtZero: true,
            // With nothing captured yet the scale would read "1 B/s, 0 B/s, 0 B/s".
            suggestedMax: 1000,
            ticks: { maxTicksLimit: 4, callback: (v) => fmtRate(v) },
          },
        },
        plugins: {
          tooltip: {
            callbacks: {
              title: (items) => this.xLabel(items[0].dataIndex),
              label: (item) => fmtRate(item.parsed.y),
            },
          },
        },
      },
    });
  }

  xLabel(i) {
    const t = this.times?.[i];
    if (t === undefined) return "";
    if (this.fileMode)
      return new Date(t * 1000).toLocaleTimeString([], { hour12: false });
    const last = this.times[this.times.length - 1];
    const d = Math.round(t - last);
    return d === 0 ? "now" : `${d}s`;
  }

  setTimeline(points, fileMode = false) {
    this.fileMode = fileMode;
    this.times = points.map((p) => p[0]);
    this.values = points.map((p) => p[1]);
    this.spikeSet.clear();
    this.redraw();
  }

  pushPoint(t, bps, spike) {
    if (this.fileMode) return;
    if (!this.times) {
      this.times = [];
      this.values = [];
    }
    const last = this.times[this.times.length - 1];
    if (last !== undefined && t <= last) {
      this.values[this.values.length - 1] = bps;
    } else {
      this.times.push(t);
      this.values.push(bps);
      if (this.times.length > 60) {
        this.times.shift();
        this.values.shift();
        this.spikeSet = new Set(
          [...this.spikeSet].map((i) => i - 1).filter((i) => i >= 0),
        );
      }
    }
    if (spike) this.spikeSet.add(this.values.length - 1);
    this.redraw();
  }

  redraw() {
    const ds = this.bw.data;
    ds.labels = this.times.map((_, i) => i);
    // Time before the first byte was seen isn't "zero traffic", it's no data: leave a gap.
    const first = this.values.findIndex((v) => v > 0);
    ds.datasets[0].data = this.values.map((v, i) =>
      first === -1 || i < first ? null : v,
    );
    const peak = Math.max(0, ...this.values);
    const now = this.values[this.values.length - 1] || 0;
    // The limit line only shows once traffic gets near it; drawn all the time it would
    // squash everyday traffic flat against the bottom of the chart.
    const limit = this.fileMode ? null : this.limit;
    const line = ds.datasets[1];
    line.hidden = !limit || peak < 0.25 * limit;
    line.data = line.hidden ? [] : this.values.map(() => limit);
    this.bw.update("none");
    const ofLimit = limit ? ` · ${fmtPct(now / limit)} OF YOUR ${fmtRate(limit)}` : "";
    this.bwStat.textContent =
      first === -1
        ? "COLLECTING…"
        : this.fileMode
          ? `PEAK ${fmtRate(peak)}`
          : `NOW ${fmtRate(now)}${ofLimit} · PEAK ${fmtRate(peak)}`;
    this.bwStat.dataset.tip = limit
      ? `Your speed test on this network measured ${fmtRate(limit)}. The dashed line shows it once traffic gets close.`
      : "Run the speed test on the Wi-Fi tab to see how close you are to this network's limit.";
  }

  /** This network's measured download speed in bytes/s, or null if it hasn't been tested. */
  setLimit(bps) {
    const v = bps || null;
    if (v === this.limit) return;
    this.limit = v;
    if (this.times) this.redraw();
  }

  setProtocols(counts) {
    const { total, items } = protoShares(counts);
    this.protoTotal.textContent = fmtCount(total);
    for (const it of items) {
      let n = this.protoNodes.get(it.name);
      if (!n) {
        const text = el("em", {});
        n = {
          seg: el("div", { class: "protobar__seg" }),
          leg: el("span", {}, el("i", {}), it.name, " ", text),
          text,
        };
        this.protoNodes.set(it.name, n);
      }
      const tip = `${it.name}: ${protoTip(it.name) || "other traffic"}`;
      n.seg.style.flexGrow = String(it.count);
      n.seg.style.background = it.color;
      n.seg.setAttribute("data-tip", `${tip} (${it.label})`);
      n.leg.firstChild.style.background = it.color;
      n.leg.setAttribute("data-tip", tip);
      n.leg.classList.toggle("is-faint", it.faint);
      n.text.textContent = it.label;
    }
    // Only touch the DOM's order when the set or ranking changed, so a tooltip that is open
    // on one of these doesn't get yanked every second.
    const key = items.map((it) => it.name).join();
    if (key !== this.protoKey) {
      this.protoKey = key;
      this.protoBar.replaceChildren(...items.map((it) => this.protoNodes.get(it.name).seg));
      this.protoLegend.replaceChildren(...items.map((it) => this.protoNodes.get(it.name).leg));
    }
  }
}

/** Protocol shares, biggest first: [{ name, count, pct, label, faint, color }] and the total. */
export function protoShares(counts) {
  const entries = ORDER.map((k) => [k, counts[k] || 0]).filter(([, v]) => v > 0);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  const items = entries
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => {
      const pct = total ? (count / total) * 100 : 0;
      return {
        name,
        count,
        pct,
        label: pct >= 1 ? `${Math.round(pct)}%` : pct > 0 ? "<1%" : "0%",
        faint: pct < 1,
        color: PROTO_COLORS[name],
      };
    });
  return { total, items };
}
