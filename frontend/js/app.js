// Dashboard entry point: wires the WebSocket stream to every panel.

import { AlertsFeed } from "./alerts.js";
import { get, post, uploadPcap } from "./api.js";
import { sound } from "./audio.js";
import { Charts } from "./charts.js";
import { compileFilter, FilterError } from "./filter.js";
import { el, fmtCount, fmtRate, icon } from "./format.js";
import { GeoMap } from "./geomap.js";
import { Inspector } from "./inspector.js";
import { NetView } from "./netview.js";
import { PacketTable } from "./table.js";
import { WifiView } from "./wifi.js";
import { connect } from "./ws.js";

const $ = (id) => document.getElementById(id);

const state = {
  status: null,
  capturingSince: null,
  generation: null,
  filterText: "",
  ifacesLoaded: false,
};

// ------------------------------------------------------------------ toasts
function toast(message, kind = "info", ms = 4000) {
  const t = el("div", {
    class: `toast${kind === "err" ? " err" : ""}`,
    role: kind === "err" ? "alert" : "status",
    text: message,
  });
  $("toasts").append(t);
  setTimeout(() => t.remove(), ms);
}

// ------------------------------------------------------------------ panels
const inspector = new Inspector({
  root: $("inspector"),
  body: $("insp-body"),
  toggle: $("btn-inspector"),
});
const table = new PacketTable({
  scroll: $("ptable-scroll"),
  spacer: $("ptable-spacer"),
  jump: $("jump-live"),
  jumpText: $("jump-live-text"),
  stat: $("table-stat"),
  onSelect: (id) => inspector.show(id),
});
const charts = new Charts({
  bwCanvas: $("bw-chart"),
  bwStat: $("bw-stat"),
  protoCanvas: $("proto-chart"),
  protoTable: $("proto-table"),
  protoTotal: $("proto-total"),
});
const geomap = new GeoMap({
  container: $("geomap"),
  stat: $("geo-stat"),
  note: $("geo-note"),
  onSelect: (ip) => ip && focusHost(ip),
  onArrive: () => sound.tick(),
});
const alerts = new AlertsFeed({
  root: $("alerts"),
  stat: $("alerts-stat"),
  onFocus: (ip) => focusHost(ip),
});
const wifi = new WifiView({ root: $("wifiview"), stat: $("nv-stat") });
const net = new NetView({
  root: $("netview"),
  stat: $("nv-stat"),
  onSelect: (ip) => focusHost(ip),
});

// ------------------------------------------------------------------ filter
const filterInput = $("filter-input");
let filterTimer = 0;

function applyFilter(text) {
  state.filterText = text;
  filterInput.value = text;
  const err = $("filter-error");
  try {
    const pred = compileFilter(text);
    err.textContent = "";
    filterInput.classList.remove("is-error");
    table.setFilter(pred);
    renderChip(text.trim());
  } catch (e) {
    if (!(e instanceof FilterError)) throw e;
    err.textContent = e.message;
    filterInput.classList.add("is-error");
  }
}

function renderChip(text) {
  const slot = $("filter-chip-slot");
  if (!text) {
    slot.replaceChildren();
    return;
  }
  const clear = el(
    "button",
    { type: "button", "aria-label": "Clear filter" },
    icon("x"),
  );
  clear.addEventListener("click", () => {
    applyFilter("");
    net.select(null);
    geomap.select(null);
  });
  slot.replaceChildren(
    el("span", { class: "filter-chip" }, el("span", { text: "FILTER" }), clear),
  );
}

filterInput.addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => applyFilter(filterInput.value), 150);
});
filterInput.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    applyFilter("");
    net.select(null);
  }
});

function focusHost(ip) {
  if (!ip) {
    if (/^ip == /.test(state.filterText)) applyFilter("");
    net.select(null);
    geomap.select(null);
    return;
  }
  applyFilter(`ip == ${ip}`);
  net.select(ip);
  geomap.select(ip);
}

// ------------------------------------------------------------------ status
function applyStatus(s) {
  if (!s) return;
  const was = state.status?.capturing;
  state.status = s;
  if (s.capturing && !was) state.capturingSince = Date.now();
  if (!s.capturing) state.capturingSince = null;
  renderModeChip();

  const btn = $("btn-capture");
  btn.className = `btn ${s.capturing ? "btn-stop" : "btn-start"}`;
  btn.replaceChildren(
    icon(s.capturing ? "player-stop" : "player-play"),
    el("span", { text: s.capturing ? "Stop" : "Start" }),
  );

  const live = s.mode === "live" || s.mode === "idle";
  $("banner").hidden = !(live && s.capture && !s.capture.ok) || s.replay;
  $("banner-text").textContent = s.capture?.hint || "";

  const geo = s.geo || {};
  $("geo-chip").textContent = `GEO ${(geo.provider || "off").toUpperCase()}`;
  $("geo-chip").title =
    geo.provider === "ip-api"
      ? "Online lookups via ip-api.com (public IPs are sent to a third party)"
      : geo.hint || "Offline DB-IP database";
  geomap.setProvider(geo.provider, geo.hint);
  if (!state.ifacesLoaded) loadInterfaces();
  else syncSelect();
}

function renderModeChip() {
  const s = state.status;
  if (!s) return;
  const chip = $("mode-chip");
  const label =
    { live: "LIVE", replay: "REPLAY", file: "FILE", idle: "IDLE" }[s.mode] ||
    s.mode.toUpperCase();
  const parts = [];
  if (s.capturing)
    parts.push(el("span", { class: "rec", "aria-hidden": "true" }));
  parts.push(el("span", { text: `${label}${s.source ? ` ${s.source}` : ""}` }));
  if (s.capturing && state.capturingSince) {
    const secs = Math.floor((Date.now() - state.capturingSince) / 1000);
    const mm = String(Math.floor(secs / 60)).padStart(2, "0");
    const ss = String(secs % 60).padStart(2, "0");
    parts.push(el("span", { class: "muted", text: `${mm}:${ss}` }));
  }
  chip.className = `chip${s.capturing ? " is-live" : ""}`;
  chip.replaceChildren(...parts);
}
setInterval(renderModeChip, 1000);

async function loadInterfaces() {
  state.ifacesLoaded = true;
  try {
    const data = await get("/api/interfaces");
    const sel = $("iface-select");
    const opts = [];
    if (state.status?.replay)
      opts.push(
        el("option", {
          value: "replay",
          text: `Replay · ${state.status.replay}`,
        }),
      );
    const groups = {
      network: "Network",
      vpn: "VPN tunnels",
      loopback: "Loopback",
      system: "System",
    };
    for (const [kind, label] of Object.entries(groups)) {
      const items = data.items.filter((i) => i.kind === kind);
      if (!items.length) continue;
      const og = el("optgroup", { label });
      for (const i of items) {
        og.append(
          el("option", {
            value: i.name,
            text: `${i.name} · ${i.label}${i.ipv4[0] ? ` · ${i.ipv4[0]}` : ""}`,
          }),
        );
      }
      opts.push(og);
    }
    sel.replaceChildren(...opts);
    syncSelect(data.default);
  } catch (e) {
    toast(e.message, "err");
  }
}

function syncSelect(fallback) {
  const s = state.status;
  const sel = $("iface-select");
  if (!s) return;
  const value =
    s.mode === "replay"
      ? "replay"
      : s.mode === "live"
        ? s.source
        : s.iface || fallback;
  if (value && [...sel.options].some((o) => o.value === value))
    sel.value = value;
}

// ------------------------------------------------------------------ stream
function onMessage(msg) {
  switch (msg.type) {
    case "snapshot": {
      state.generation = msg.generation;
      applyStatus(msg.status);
      table.reset(msg.packets || []);
      alerts.reset(msg.alerts || []);
      charts.setTimeline(msg.timeline || [], msg.mode === "file");
      applyStats(msg.stats, true);
      net.update(msg.netview);
      table.setFlagged(flaggedSet(msg.netview));
      geomap.reset();
      geomap.update(msg.geo?.items || []);
      if (!msg.packets?.length) inspector.clear();
      if (msg.wifi) {
        state.wifi = msg.wifi;
        if (state.tab === "wifi") wifi.update(msg.wifi);
      }
      break;
    }
    case "packets":
      if (
        msg.generation !== undefined &&
        state.generation !== null &&
        msg.generation !== state.generation
      )
        return;
      table.append(msg.items);
      break;
    case "alert":
      alerts.add(msg.alert);
      if (msg.alert.severity === "high" || msg.alert.severity === "critical")
        sound.alarm();
      break;
    case "alert_update":
      alerts.update(msg.alert);
      break;
    case "stats":
      applyStats(msg);
      break;
    case "netview":
      net.update(msg);
      table.setFlagged(flaggedSet(msg));
      break;
    case "geo":
      geomap.update(msg.items || []);
      break;
    case "status":
      applyStatus(msg);
      break;
    case "wifi":
      state.wifi = msg;
      if (state.tab === "wifi") wifi.update(msg);
      break;
    default:
      break;
  }
}

function flaggedSet(view) {
  const set = new Set();
  for (const h of [
    ...(view?.internet || []),
    ...(view?.lan || []),
    view?.gateway,
  ].filter(Boolean)) {
    if (h.severity === "high" || h.severity === "critical") set.add(h.ip);
  }
  return set;
}

function applyStats(s, initial = false) {
  if (!s) return;
  const file = state.status?.mode === "file";
  $("ro-pps").textContent = file ? fmtCount(s.packets) : fmtCount(s.pps);
  $("ro-bps").textContent = file
    ? `${(s.bytes / 1e6).toFixed(1)} MB`
    : fmtRate(s.bps);
  $("ro-pps").previousElementSibling.textContent = file
    ? "PACKETS"
    : "PACKETS/S";
  $("ro-bps").previousElementSibling.textContent = file ? "TOTAL" : "BANDWIDTH";
  charts.setProtocols(s.protocols || {});
  if (!initial && !file) charts.pushPoint(s.t, s.bps, s.spike);
  if (s.dropped)
    $("table-stat").title =
      `${s.dropped} packets dropped because the app couldn't keep up`;
}

const socket = connect(onMessage, (st) => {
  if (st === "open" && state.tab === "wifi") socket?.send("wifi:on");
  if (st === "denied") {
    $("mode-chip").replaceChildren(
      el("span", { class: "t-alert", text: "LOCKED" }),
    );
    toast(
      "Session expired. Open the link printed in the terminal again.",
      "err",
      10000,
    );
  } else if (st === "closed") {
    $("mode-chip").replaceChildren(
      el("span", { class: "muted", text: "RECONNECTING" }),
    );
  }
});

// ------------------------------------------------------------------ controls
$("btn-capture").addEventListener("click", async () => {
  sound.unlock();
  const s = state.status;
  try {
    if (s?.capturing) {
      applyStatus(await post("/api/capture/stop"));
    } else {
      const iface = $("iface-select").value;
      applyStatus(await post("/api/capture/start", { iface }));
      sound.start();
      net.sweep();
    }
  } catch (e) {
    toast(e.message, "err", 7000);
  }
});

$("iface-select").addEventListener("change", async () => {
  if (!state.status?.capturing && state.status?.mode !== "idle") return;
  try {
    applyStatus(
      await post("/api/capture/start", { iface: $("iface-select").value }),
    );
    net.sweep();
  } catch (e) {
    toast(e.message, "err", 7000);
    syncSelect();
  }
});

$("btn-clear").addEventListener("click", async () => {
  try {
    await post("/api/clear");
    inspector.clear();
  } catch (e) {
    toast(e.message, "err");
  }
});

const exportDialog = $("export-dialog");
$("btn-export").addEventListener("click", () => exportDialog.showModal());
$("export-cancel").addEventListener("click", () => exportDialog.close());
function download(url) {
  const a = el("a", { href: url, download: "" });
  document.body.append(a);
  a.click();
  a.remove();
  exportDialog.close();
}
$("export-full").addEventListener("click", () => download("/api/export.pcap"));
$("export-headers").addEventListener("click", () =>
  download("/api/export.pcap?headers_only=1"),
);

$("btn-upload").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", async (ev) => {
  const file = ev.target.files?.[0];
  ev.target.value = "";
  if (!file) return;
  const limit = (state.status?.limits?.upload_mb || 200) * 1024 * 1024;
  if (file.size > limit) {
    toast(
      `That file is over ${state.status?.limits?.upload_mb || 200} MB.`,
      "err",
    );
    return;
  }
  toast(`Analysing ${file.name}…`, "info", 2500);
  try {
    const r = await uploadPcap(file);
    toast(
      `${file.name}: ${r.packets.toLocaleString()} packets${r.skipped ? `, ${r.skipped} skipped` : ""}${r.truncated ? " (truncated)" : ""}.`,
    );
    net.sweep();
  } catch (e) {
    toast(e.message, "err", 8000);
  }
});

function renderMute() {
  const b = $("btn-mute");
  b.setAttribute("aria-pressed", sound.muted ? "true" : "false");
  b.setAttribute("aria-label", sound.muted ? "Unmute sounds" : "Mute sounds");
  b.title = sound.muted ? "Sounds off" : "Sounds on";
  b.replaceChildren(icon(sound.muted ? "volume-off" : "volume"));
}
$("btn-mute").addEventListener("click", () => {
  sound.setMuted(!sound.muted);
  renderMute();
});
renderMute();

const TABS = [
  ["tab-map", "map"],
  ["tab-flows", "flows"],
  ["tab-wifi", "wifi"],
];
state.tab = "map";
function setTab(tab) {
  state.tab = tab;
  for (const [id, name] of TABS) $(id).setAttribute("aria-selected", name === tab ? "true" : "false");
  const isWifi = tab === "wifi";
  $("netview").hidden = isWifi;
  $("wifiview").hidden = !isWifi;
  net.setTab(tab);
  if (isWifi) {
    socket.send("wifi:on"); // tells the server to start pinging
    wifi.resize();
    if (state.wifi) wifi.update(state.wifi);
  } else if (net.view) {
    net.renderStat();
  }
}
for (const [id, tab] of TABS) $(id).addEventListener("click", () => setTab(tab));
// Keep the Wi-Fi check running while its tab is open (the server stops pinging 15 s after the last one).
setInterval(() => {
  if (state.tab === "wifi" && !document.hidden) socket.send("wifi:on");
}, 5000);

document.addEventListener("keydown", (ev) => {
  if (ev.key === "/" && document.activeElement !== filterInput) {
    ev.preventDefault();
    filterInput.focus();
  }
});
