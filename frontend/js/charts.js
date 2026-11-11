// Bandwidth line chart and protocol donut (Chart.js, vendored).

import { el, fmtCount, fmtRate } from "./format.js";

export const PROTO_COLORS = {
  TLS: "#00ff41",
  TCP: "#00b52e",
  QUIC: "#7dffa0",
  UDP: "#00f3ff",
  DNS: "#0096a0",
  HTTP: "#ffb000",
  ICMP: "#8a93a3",
  ARP: "#4f5868",
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
    color: "#4f5868",
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
  constructor({ bwCanvas, bwStat, protoCanvas, protoTable, protoTotal }) {
    setupDefaults();
    this.bwStat = bwStat;
    this.protoTable = protoTable;
    this.protoTotal = protoTotal;
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
    this.donut = new window.Chart(protoCanvas, {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [
          {
            data: [],
            backgroundColor: [],
            borderWidth: 2,
            borderColor: "#12151c",
            hoverOffset: 0,
          },
        ],
      },
      options: {
        responsive: false,
        cutout: "80%",
        plugins: { tooltip: { enabled: false } },
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
    ds.datasets[0].data = this.values;
    this.bw.update("none");
    const peak = Math.max(0, ...this.values);
    const now = this.values[this.values.length - 1] || 0;
    this.bwStat.textContent = this.fileMode
      ? `PEAK ${fmtRate(peak)}`
      : `NOW ${fmtRate(now)} · PEAK ${fmtRate(peak)}`;
  }

  setProtocols(counts) {
    const entries = ORDER.map((k) => [k, counts[k] || 0]).filter(
      ([, v]) => v > 0,
    );
    const total = entries.reduce((s, [, v]) => s + v, 0);
    const d = this.donut.data;
    d.labels = entries.map(([k]) => k);
    d.datasets[0].data = entries.map(([, v]) => v);
    d.datasets[0].backgroundColor = entries.map(([k]) => PROTO_COLORS[k]);
    this.donut.update("none");
    this.protoTotal.textContent = fmtCount(total);
    const rows = entries
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([k, v]) => {
        const name = el("td", { text: k });
        name.style.color = PROTO_COLORS[k];
        return el(
          "tr",
          {},
          name,
          el("td", { text: `${total ? Math.round((v / total) * 100) : 0}%` }),
        );
      });
    this.protoTable.replaceChildren(...rows);
  }
}
