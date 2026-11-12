// Network view: isometric Map tab and flat Flows tab. See docs/DESIGN.md.
// Elements are kept by key and updated in place so the packet dashes and the
// breathing red glow don't restart every second.

import {
  ago,
  clock,
  el,
  fmtPct,
  fmtRate,
  icon,
  svg,
  truncate,
} from "./format.js";
import { alertInfo } from "./glossary.js";
import { device, footprintDiamond, slab } from "./iso.js";
import {
  airPath,
  columnRows,
  edgeStyle,
  f,
  fitMiddle,
  GATEWAY_SLOT,
  gridPath,
  LAN_SLOTS,
  RankHold,
  ribbons,
  screenAt,
  SELF_SLOT,
  SLAB_Z,
  slabGeometry,
  slabLabelChars,
  slabPoint,
  TOP_INTERNET,
} from "./netlayout.js";

const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const sevClass = (s) =>
  s === "high" || s === "critical" ? "high" : s === "medium" ? "medium" : null;
const KIND_LABEL = {
  self: "This Mac",
  gateway: "Gateway",
  lan: "Home device",
  internet: "Internet host",
};

export class NetView {
  constructor({ root, stat, onSelect }) {
    this.root = root;
    this.stat = stat;
    this.onSelect = onSelect;
    this.tab = "map";
    this.view = null;
    this.selected = null;
    this.hoverKey = null;
    this.rank = new RankHold(3);
    this.lanRank = new RankHold(3);
    this.incidentIdx = 0;
    this.knownIncidents = new Set();
    this.calloutSeen = new Set();
    this.incSeen = new Map();
    this.nodes = new Map();
    this.edges = new Map();
    this.flowItems = new Map();
    this.ready = false;

    this.svg = svg("svg", {
      role: "img",
      "aria-label":
        "Network map of this Mac, the router, home devices and internet hosts",
    });
    this.buildDefs();
    this.floorG = svg("g", { class: "nv-floor" });
    this.staticG = svg("g");
    this.edgesG = svg("g");
    this.nodesG = svg("g");
    this.calloutsG = svg("g");
    this.flowsG = svg("g");
    this.sweepRect = svg("rect", {
      class: "sweep",
      x: 0,
      y: 0,
      height: "100%",
    });
    this.mapG = svg(
      "g",
      {},
      this.staticG,
      this.edgesG,
      this.nodesG,
      this.calloutsG,
    );
    this.svg.append(this.floorG, this.mapG, this.flowsG, this.sweepRect);
    this.incident = el("div", { class: "incident hud-notch is-quiet" });
    this.hovercard = el("div", {
      class: "hovercard hud-brackets",
      "aria-hidden": "true",
    });
    root.append(this.svg, this.incident, this.hovercard);

    this.svg.addEventListener("mouseover", (ev) => this.onHover(ev));
    this.svg.addEventListener("mouseleave", () => this.setHover(null));
    this.svg.addEventListener("click", (ev) => this.onClick(ev));
    this.incident.addEventListener("click", (ev) => this.onIncidentClick(ev));
    new ResizeObserver(() => this.resize()).observe(root);
    this.resize();
  }

  // ------------------------------------------------------------------ setup
  buildDefs() {
    const defs = svg("defs");
    const glow = svg(
      "filter",
      // userSpaceOnUse: a horizontal line has a zero-height bounding box, which
      // would otherwise clip the glowing Mac-to-router trunk to nothing.
      {
        id: "nv-glow",
        filterUnits: "userSpaceOnUse",
        x: -4000,
        y: -4000,
        width: 12000,
        height: 12000,
      },
      svg("feGaussianBlur", { stdDeviation: "2.5", result: "b" }),
      svg(
        "feMerge",
        {},
        svg("feMergeNode", { in: "b" }),
        svg("feMergeNode", { in: "SourceGraphic" }),
      ),
    );
    const red = svg(
      "radialGradient",
      { id: "nv-red-glow" },
      svg("stop", {
        offset: "0%",
        "stop-color": "#ff003c",
        "stop-opacity": ".55",
      }),
      svg("stop", {
        offset: "100%",
        "stop-color": "#ff003c",
        "stop-opacity": "0",
      }),
    );
    const amber = svg(
      "radialGradient",
      { id: "nv-amber-glow" },
      svg("stop", {
        offset: "0%",
        "stop-color": "#ffb000",
        "stop-opacity": ".45",
      }),
      svg("stop", {
        offset: "100%",
        "stop-color": "#ffb000",
        "stop-opacity": "0",
      }),
    );
    this.gridPattern = svg(
      "pattern",
      { id: "nv-grid", width: 24, height: 24, patternUnits: "userSpaceOnUse" },
      svg("path", {
        d: "M24 0H0V24",
        fill: "none",
        stroke: "rgba(0,243,255,.07)",
        "stroke-width": 1,
      }),
    );
    const fade = svg(
      "radialGradient",
      { id: "nv-fade-g", cx: "45%", cy: "55%", r: "65%" },
      svg("stop", { offset: "0%", "stop-color": "#fff", "stop-opacity": "1" }),
      svg("stop", {
        offset: "100%",
        "stop-color": "#fff",
        "stop-opacity": "0",
      }),
    );
    this.maskRect = svg("rect", {
      x: 0,
      y: 0,
      width: "100%",
      height: "100%",
      fill: "url(#nv-fade-g)",
    });
    const mask = svg("mask", { id: "nv-fade" }, this.maskRect);
    const sweep = svg(
      "linearGradient",
      { id: "nv-sweep", x1: "0", x2: "1" },
      svg("stop", {
        offset: "0%",
        "stop-color": "#00f3ff",
        "stop-opacity": "0",
      }),
      svg("stop", {
        offset: "50%",
        "stop-color": "#00f3ff",
        "stop-opacity": ".06",
      }),
      svg("stop", {
        offset: "100%",
        "stop-color": "#00f3ff",
        "stop-opacity": "0",
      }),
    );
    const hatch = svg(
      "pattern",
      {
        id: "nv-hatch",
        width: 6,
        height: 6,
        patternUnits: "userSpaceOnUse",
        patternTransform: "rotate(45)",
      },
      svg("rect", { width: 6, height: 6, fill: "rgba(255,255,255,.02)" }),
      svg("line", {
        x1: 0,
        y1: 0,
        x2: 0,
        y2: 6,
        stroke: "rgba(255,255,255,.05)",
        "stroke-width": 2,
      }),
    );
    defs.append(glow, red, amber, this.gridPattern, fade, mask, sweep, hatch);
    this.svg.append(defs);
  }

  resize() {
    const W = Math.max(480, this.root.clientWidth);
    const H = Math.max(320, this.root.clientHeight);
    if (W === this.W && H === this.H) return;
    this.W = W;
    this.H = H;
    this.svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const g = slabGeometry(W, H);
    this.geom = g;
    this.gridPattern.setAttribute(
      "patternTransform",
      `translate(${g.ox} ${g.wy}) matrix(1 .5 -1 .5 0 0)`,
    );
    this.floorG.replaceChildren(
      svg("rect", {
        x: 0,
        y: 0,
        width: W,
        height: H,
        fill: "url(#nv-grid)",
        mask: "url(#nv-fade)",
      }),
    );
    this.sweepRect.setAttribute("width", Math.round(W * 0.35));
    this.buildStatic();
    this.render();
  }

  buildStatic() {
    const g = this.geom;
    const slabG = svg("g", {
      class: "slab",
      transform: `translate(${g.ox} ${g.wy})`,
    });
    slab(slabG, g.S, SLAB_Z);
    // Zone label on the floor in front of the slab's front-left face (skewed along
    // the +x axis). It sits below the front row's two-line labels (they reach about
    // 40px under a device), so the two never share a spot.
    const [lx, ly] = screenAt({ x: g.S * 0.3, y: g.S + 10, z: 0 }, g);
    this.slabLabel = svg("text", {
      class: "slab-label",
      transform: `matrix(1 .5 0 1 ${f(lx)} ${f(ly + 46)})`,
    });
    this.colX = Math.min(Math.max(g.rightEdge + 96, 0), this.W - 236);
    this.colHead = svg("text", { class: "col-head", x: this.colX - 12, y: 28 });
    const rule = svg("line", {
      class: "col-rule",
      x1: this.colX - 12,
      x2: this.colX + 12,
      y1: 37,
      y2: 37,
    });
    this.staticG.replaceChildren(slabG, this.slabLabel, this.colHead, rule);
  }

  // ------------------------------------------------------------------- data
  setTab(tab) {
    this.tab = tab;
    this.root.classList.toggle("nv-flows", tab === "flows");
    this.setHover(null);
    this.render();
  }

  update(view) {
    this.view = view;
    const t = view.now || Date.now() / 1000;
    this.order = this.rank.update(
      (view.internet || []).map((h) => h.ip),
      t,
    );
    this.lanOrder = this.lanRank.update(
      (view.lan || []).map((h) => h.ip),
      t,
    );
    this.render();
    this.renderIncident();
    this.renderStat();
  }

  select(ip) {
    this.selected = ip;
    this.render();
  }

  sweep() {
    this.sweepRect.classList.remove("go");
    void this.sweepRect.getBoundingClientRect();
    this.sweepRect.classList.add("go");
  }

  render() {
    if (!this.geom) return;
    this.mapG.setAttribute("display", this.tab === "map" ? "inline" : "none");
    this.flowsG.setAttribute(
      "display",
      this.tab === "flows" ? "inline" : "none",
    );
    this.incident.hidden = this.tab !== "map";
    if (!this.view) return;
    if (this.tab === "map") this.renderMap();
    else this.renderFlows();
    if (!this.ready)
      requestAnimationFrame(() => {
        this.ready = true;
        this.root.classList.add("nv-ready");
      });
  }

  renderStat() {
    if (this.tab === "wifi") return;
    const v = this.view;
    const parts = [
      el("span", { text: `${v.counts?.hosts ?? 0} HOSTS` }),
      el("span", { class: "dot", text: "·" }),
      el("span", { text: fmtRate(v.total_bps) }),
    ];
    const flagged = v.counts?.flagged ?? 0;
    if (flagged)
      parts.push(
        el("span", { class: "dot", text: "·" }),
        el("span", { class: "t-alert", text: `${flagged} FLAGGED` }),
      );
    this.stat.replaceChildren(...parts);
  }

  // -------------------------------------------------------------------- map
  layoutMap() {
    const v = this.view;
    const g = this.geom;
    const items = [];
    const selfW = slabPoint(...SELF_SLOT, g);
    const gwW = slabPoint(...GATEWAY_SLOT, g);
    const toScreen = (w) => screenAt(w, g);
    if (v.self)
      items.push({
        key: "self",
        host: v.self,
        world: selfW,
        pos: toScreen(selfW),
        zone: "slab",
      });
    const gwHost = v.gateway || {
      ip: "",
      kind: "gateway",
      device: "router",
      bps: 0,
    };
    items.push({
      key: "gw",
      host: { ...gwHost, kind: "gateway", device: "router" },
      world: gwW,
      pos: toScreen(gwW),
      zone: "slab",
    });

    const lanByIp = new Map((v.lan || []).map((h) => [h.ip, h]));
    let lan = (this.lanOrder || [])
      .map((ip) => lanByIp.get(ip))
      .filter(Boolean);
    const more = v.lan_more || 0;
    const slots = LAN_SLOTS.slice();
    if (more > 0) lan = lan.slice(0, 5);
    lan.forEach((h, i) => {
      const w = slabPoint(...slots[i], g);
      items.push({
        key: `h:${h.ip}`,
        host: h,
        world: w,
        pos: toScreen(w),
        zone: "slab",
      });
    });
    if (more > 0) {
      const w = slabPoint(...slots[5], g);
      items.push({
        key: "lan-more",
        host: {
          ip: "",
          kind: "lan",
          device: "unknown",
          name: `+${more + 1} devices`,
          bps: 0,
        },
        world: w,
        pos: toScreen(w),
        zone: "slab",
        others: true,
      });
    }

    const inetByIp = new Map((v.internet || []).map((h) => [h.ip, h]));
    const inet = (this.order || [])
      .map((ip) => inetByIp.get(ip))
      .filter(Boolean)
      .slice(0, TOP_INTERNET);
    const others = v.others && v.others.count > 0;
    const rows = columnRows(
      inet.length + (others ? 1 : 0),
      this.H,
      items[items.length > 1 ? 1 : 0]?.pos[1] ?? this.H / 2,
    );
    const scale = inet.length + (others ? 1 : 0) > 5 ? 0.8 : 1;
    inet.forEach((h, i) => {
      items.push({
        key: `h:${h.ip}`,
        host: h,
        pos: [this.colX, rows[i]],
        zone: "column",
        scale,
      });
    });
    if (others) {
      items.push({
        key: "others",
        host: {
          ip: "",
          kind: "internet",
          device: "others",
          name: `+${v.others.count} hosts`,
          bps: v.others.bps,
          share: v.others.share,
        },
        pos: [this.colX, rows[rows.length - 1]],
        zone: "column",
        scale,
        others: true,
      });
    }
    return { items, selfW, gwW };
  }

  renderMap() {
    const v = this.view;
    const g = this.geom;
    const { items, selfW, gwW } = this.layoutMap();
    const inetCount = v.counts?.internet ?? 0;
    this.colHead.textContent = `INTERNET · ${inetCount} HOST${inetCount === 1 ? "" : "S"}`;
    // A small slab has no room for the subnet along its edge.
    this.slabLabel.textContent = `HOME NETWORK${v.network && g.S >= 300 ? ` · ${v.network}` : ""}`;

    // ---- edges
    const wanted = new Set();
    const gwItem = items.find((i) => i.key === "gw");
    const routerTop = [gwItem.pos[0] + 6, gwItem.pos[1] - 20];
    const totalIn = [...(v.internet || []), ...(v.lan || [])].reduce(
      (s, h) => s + (h.bytes_in || 0),
      0,
    );
    const totalOut = [...(v.internet || []), ...(v.lan || [])].reduce(
      (s, h) => s + (h.bytes_out || 0),
      0,
    );
    if (v.self) {
      const [ax, ay] = screenAt(selfW, g);
      const [bx, by] = screenAt(gwW, g);
      const d =
        totalIn >= totalOut
          ? `M${f(bx)} ${f(by)}L${f(ax)} ${f(ay)}`
          : `M${f(ax)} ${f(ay)}L${f(bx)} ${f(by)}`;
      this.edge("trunk", d, v.total_bps, null, wanted);
    }
    for (const it of items) {
      const h = it.host;
      if (it.key === "self" || it.key === "gw") continue;
      const inbound = (h.bytes_in || 0) >= (h.bytes_out || 0);
      let d;
      if (it.zone === "slab") {
        d = inbound ? gridPath(it.world, gwW, g) : gridPath(gwW, it.world, g);
      } else {
        const end = [
          it.pos[0] - 14 * (it.scale || 1),
          it.pos[1] - 8 * (it.scale || 1),
        ];
        d = inbound ? airPath(end, routerTop) : airPath(routerTop, end);
      }
      this.edge(
        `e:${it.key}`,
        d,
        it.others ? (h.bps || 0) * 0.5 : h.bps,
        sevClass(h.severity),
        wanted,
        it.key,
      );
    }
    for (const [key, e] of this.edges)
      if (!wanted.has(key)) {
        e.g.remove();
        this.edges.delete(key);
      }

    // ---- nodes
    const seen = new Set();
    for (const it of items) {
      seen.add(it.key);
      this.node(it);
    }
    for (const [key, n] of this.nodes)
      if (!seen.has(key)) {
        n.g.remove();
        this.nodes.delete(key);
      }

    // ---- callouts: the two most severe flagged nodes on the slab
    const flagged = items
      .filter((i) => i.zone === "slab" && sevClass(i.host.severity))
      .sort((a, b) => (SEV[b.host.severity] || 0) - (SEV[a.host.severity] || 0))
      .slice(0, 2);
    const placed = [];
    this.calloutsG.replaceChildren(
      ...flagged.map((it) => this.callout(it, placed)),
    );
    if (this.hoverKey) this.applyHover();
  }

  edge(key, d, bps, sev, wanted, nodeKey) {
    wanted.add(key);
    let e = this.edges.get(key);
    if (!e) {
      const g = svg("g", {
        class: "edge",
        "data-key": key,
        "data-node": nodeKey || "",
      });
      const track = svg("path", { class: "edge-track" });
      const flow = svg("path", { class: "edge-flow" });
      g.append(track, flow);
      this.edgesG.append(g);
      e = { g, track, flow, gap: null, dur: null };
      this.edges.set(key, e);
    }
    const st = edgeStyle(bps);
    e.track.setAttribute("d", d);
    e.flow.setAttribute("d", d);
    e.track.setAttribute("stroke-width", st.width);
    e.flow.setAttribute("stroke-width", Math.max(1.2, st.width * 0.7));
    e.g.setAttribute(
      "class",
      `edge${st.idle ? " is-idle" : ""}${sev ? ` is-${sev}` : ""}`,
    );
    e.flow.setAttribute("display", st.idle ? "none" : "inline");
    e.flow.classList.toggle("hot", !!st.hot);
    if (!st.idle && (st.gap !== e.gap || st.dur !== e.dur)) {
      e.flow.style.setProperty("--gap", st.gap);
      e.flow.style.setProperty("--dur", `${st.dur}s`);
      e.gap = st.gap;
      e.dur = st.dur;
    }
  }

  node(it) {
    const h = it.host;
    let n = this.nodes.get(it.key);
    const kind = it.others ? "others" : h.device || "unknown";
    if (!n) {
      const g = svg("g", { class: "node", "data-key": it.key, tabindex: "-1" });
      const under = svg("g");
      const model = svg("g");
      const labels = svg("g");
      g.append(under, model, labels);
      this.nodesG.append(g);
      n = { g, under, model, labels, kind: null, meta: null };
      this.nodes.set(it.key, n);
    }
    if (n.kind !== kind) {
      n.model.replaceChildren();
      n.meta = device(n.model, kind === "others" ? "others" : kind);
      n.kind = kind;
    }
    const sev = sevClass(h.severity);
    const isSel = !!h.ip && h.ip === this.selected;
    const cls = [
      "node",
      this.ready && "node-move",
      it.key === "self" && "is-self",
      sev && `is-${sev}`,
      isSel && "is-selected",
      it.others && "is-others",
    ]
      .filter(Boolean)
      .join(" ");
    n.g.setAttribute("class", cls);
    n.g.dataset.ip = h.ip || "";
    const scale = it.scale || (it.zone === "slab" ? 1.3 : 1);
    n.g.style.transform = `translate(${f(it.pos[0])}px, ${f(it.pos[1])}px)`;
    n.model.setAttribute("transform", scale !== 1 ? `scale(${scale})` : "");
    n.item = it;

    // Floor treatments: red breathing ellipse, cyan targeting diamond.
    const under = [];
    if (sev)
      under.push(
        svg("ellipse", {
          class: `flag-ellipse breathe${sev === "medium" ? " warn" : ""}`,
          cx: 0,
          cy: 0,
          rx: 28 * scale,
          ry: 14 * scale,
        }),
      );
    if (isSel)
      under.push(
        svg("polygon", {
          class: "target-diamond",
          points: footprintDiamond(n.meta.w * scale, n.meta.d * scale),
        }),
      );
    const sig = `${sev}|${isSel}|${scale}`;
    if (n.underSig !== sig) {
      n.under.replaceChildren(...under);
      n.underSig = sig;
    }

    // Labels.
    const name =
      it.key === "self"
        ? "This Mac"
        : it.key === "gw"
          ? "Gateway · router"
          : it.zone === "slab" && !it.others
            ? this.displayName(h)
            : h.name || h.ip || "";
    let sub;
    if (it.key === "self" || it.key === "gw") sub = h.ip || "";
    else if (it.others) sub = fmtRate(h.bps);
    else if (it.zone === "column" && sev) sub = h.reason || "";
    else if (it.zone === "column")
      sub = [h.cc, fmtRate(h.bps), fmtPct(h.share)].filter(Boolean).join(" · ");
    else sub = h.ip;
    // Labels on the slab share a row with their neighbours: size them to the gap.
    // This Mac and the router sit alone on their row, so they can use the full width.
    const room =
      it.key === "self" || it.key === "gw"
        ? { name: 18, sub: 30 }
        : slabLabelChars(this.geom.S);
    const labelSig = `${name}|${sub}|${it.zone}|${scale}|${room.name}`;
    if (n.labelSig !== labelSig) {
      n.labelSig = labelSig;
      if (it.zone === "column") {
        const x = 20 * scale + 4;
        n.labels.replaceChildren(
          svg("text", {
            class: "node-label",
            x,
            y: -4,
            text: truncate(name, 26),
          }),
          svg("text", { class: "node-sub", x, y: 10, text: truncate(sub, 34) }),
        );
      } else {
        n.labels.replaceChildren(
          svg("text", {
            class: "node-label",
            x: 0,
            y: 26,
            "text-anchor": "middle",
            text: truncate(name, room.name),
          }),
          svg("text", {
            class: "node-sub",
            x: 0,
            y: 39,
            "text-anchor": "middle",
            text: fitMiddle(sub, room.sub),
          }),
        );
      }
    }
  }

  /** Two devices both called "iPhone" become "iPhone 1" and "iPhone 2" (ordered by address). */
  displayName(h) {
    const base = h.name || h.ip || "";
    const same = (this.view?.lan || []).filter((x) => (x.name || x.ip) === base);
    if (same.length < 2) return base;
    const order = same.map((x) => x.ip).sort();
    return `${base} ${order.indexOf(h.ip) + 1}`;
  }

  /** The name the map shows for an address (This Mac, Gateway, a host name), else the address. */
  nameFor(ip) {
    const v = this.view;
    if (!v || !ip) return ip;
    if (v.self?.ip === ip) return "This Mac";
    if (v.gateway?.ip === ip) return "Gateway";
    const lan = (v.lan || []).find((x) => x.ip === ip);
    if (lan) return lan.name && lan.name !== ip ? this.displayName(lan) : ip;
    const h = (v.internet || []).find((x) => x.ip === ip);
    return h?.name && h.name !== ip ? h.name : ip;
  }

  /** Rectangles the callout tags must stay clear of (incident card, internet column). */
  obstacles() {
    const out = [];
    if (!this.incident.hidden) {
      out.push([
        this.incident.offsetLeft - 6,
        this.incident.offsetTop - 6,
        this.incident.offsetWidth + 12,
        this.incident.offsetHeight + 12,
      ]);
    }
    out.push([this.colX - 30, 0, this.W - this.colX + 30, this.H]);
    return out;
  }

  callout(it, placed) {
    const h = it.host;
    const sev = sevClass(h.severity);
    const warn = sev === "medium" ? " warn" : "";
    const height = (this.nodes.get(it.key)?.meta?.height || 16) * 1.3 + 6;
    const [x, y] = it.pos;
    // Two devices can raise the same alert: say which one this tag belongs to.
    const who =
      it.key === "self"
        ? "This Mac"
        : fitMiddle(it.zone === "slab" ? this.displayName(h) : h.name || h.ip || "", 14);
    const k = `${(h.title || "Alert").toUpperCase()} · ${who}`;
    const v = truncate(h.reason || "", 34);
    const w = Math.max(k.length * 7.4, v.length * 6.3) + 22;
    const tagH = 34;
    // Other devices on the slab (body and two-line label) are obstacles too.
    const nodeRects = [];
    for (const [key, n] of this.nodes) {
      if (key === it.key || !n.item || n.item.zone === "column") continue;
      const [nx, ny] = n.item.pos;
      const nh = (n.meta?.height || 16) * 1.3 + 6;
      nodeRects.push([nx - 30, ny - nh, 60, nh + 8]);
      nodeRects.push([nx - 64, ny + 15, 128, 30]);
    }
    const blocked = [...this.obstacles(), ...nodeRects, ...placed];
    const hits = (r) =>
      blocked.some(
        (b) =>
          r[0] < b[0] + b[2] &&
          r[0] + r[2] > b[0] &&
          r[1] < b[1] + b[3] &&
          r[1] + r[3] > b[1],
      );
    const inside = (r) =>
      r[0] >= 8 &&
      r[1] >= 8 &&
      r[0] + r[2] <= this.W - 8 &&
      r[1] + r[3] <= this.H - 8;
    // Elbow: vertical from the device, a short 26.57° run along the grid, then horizontal.
    const shapes = [
      { up: true, sx: 1 },
      { up: true, sx: -1 },
      { up: false, sx: 1 },
      { up: false, sx: -1 },
    ].map(({ up, sx }) => {
      const p0 = up ? [x, y - height] : [x, y + 8];
      const p1 = [x, p0[1] + (up ? -20 : 46)];
      const p2 = [x + sx * 12, p1[1] + (up ? -6 : 6)];
      const p3 = [x + sx * 28, p2[1]];
      const tx = sx > 0 ? p3[0] : p3[0] - w;
      const rect = [tx, p3[1] - 17, w, tagH];
      // The leader line must be clear too, not just the tag at its end.
      const legs = [
        [x - 2, Math.min(p0[1], p1[1]), 4, Math.abs(p0[1] - p1[1])],
        [Math.min(p2[0], p3[0]), p3[1] - 2, Math.abs(p3[0] - p2[0]) + 2, 4],
      ];
      return { pts: [p0, p1, p2, p3], rect, legs };
    });
    const pick =
      shapes.find((s) => inside(s.rect) && ![s.rect, ...s.legs].some(hits)) ||
      shapes.find((s) => inside(s.rect) && !hits(s.rect)) ||
      shapes.find((s) => inside(s.rect)) ||
      shapes[0];
    placed.push(pick.rect);
    const [p0, p1, p2, p3] = pick.pts;
    const line = svg("path", {
      class: `callout-line${warn}`,
      d: `M${f(p0[0])} ${f(p0[1])}L${f(p1[0])} ${f(p1[1])}L${f(p2[0])} ${f(p2[1])}L${f(p3[0])} ${f(p3[1])}`,
    });
    const [tx, ty] = pick.rect;
    const notch = `M${f(tx)} ${f(ty)}H${f(tx + w - 8)}L${f(tx + w)} ${f(ty + 8)}V${f(ty + tagH)}H${f(tx)}Z`;
    const tag = svg(
      "g",
      { class: `callout-tag${warn}` },
      svg("path", { d: notch, class: "tag-bg" }),
      svg("text", { class: "k", x: f(tx + 10), y: f(ty + 15), text: k }),
      svg("text", { class: "v", x: f(tx + 10), y: f(ty + 28), text: v }),
    );
    const id = `${it.key}|${h.alert_id}`;
    const g = svg(
      "g",
      { class: this.calloutSeen.has(id) ? "" : "callout-new" },
      line,
      tag,
    );
    this.calloutSeen.add(id);
    return g;
  }

  // ------------------------------------------------------------------ flows
  renderFlows() {
    const v = this.view;
    const W = this.W,
      H = this.H;
    const byIp = new Map(
      [...(v.internet || []), ...(v.lan || [])].map((h) => [h.ip, h]),
    );
    const rows = [];
    for (const ip of this.order || [])
      if (byIp.has(ip)) rows.push(byIp.get(ip));
    for (const ip of this.lanOrder || []) {
      const h = byIp.get(ip);
      if (h && (h.bytes60 > 0 || sevClass(h.severity))) rows.push(h);
    }
    if (v.others && v.others.count > 0) {
      rows.push({
        ip: "",
        key: "others",
        name: `+${v.others.count} other hosts`,
        bps: v.others.bps,
        share: v.others.share,
        others: true,
      });
    }
    const usable = rows.slice(0, Math.max(3, Math.floor((H - 120) / 26)));
    const geo = ribbons(
      usable.map((h) => ({
        key: h.key || h.ip,
        share: Math.max(h.share || 0, 0.001),
      })),
      W,
      H,
    );
    const x1 = geo.x1;
    const wanted = new Set();

    // This Mac bar
    let bar = this.flowItems.get("bar");
    if (!bar) {
      bar = {
        g: svg("g"),
        rect: svg("rect", { class: "self-bar" }),
        label: svg("text", { class: "self-label", text: "THIS MAC" }),
      };
      bar.g.append(bar.rect, bar.label);
      this.flowsG.append(bar.g);
      this.flowItems.set("bar", bar);
    }
    wanted.add("bar");
    bar.rect.setAttribute("x", geo.bar.x);
    bar.rect.setAttribute("y", geo.bar.y);
    bar.rect.setAttribute("width", 8);
    bar.rect.setAttribute("height", Math.max(2, geo.bar.h));
    bar.label.setAttribute("x", geo.bar.x);
    bar.label.setAttribute("y", geo.bar.y - 10);

    const hogs = new Map(
      (v.incidents || [])
        .filter((i) => i.kind === "bandwidth_hog")
        .map((i) => [i.hosts?.[0], i]),
    );
    geo.items.forEach((it, i) => {
      const h = usable[i];
      const key = `r:${it.key || "others"}`;
      wanted.add(key);
      let r = this.flowItems.get(key);
      if (!r) {
        const g = svg("g", { class: "ribbon", "data-ip": h.ip || "" });
        const fill = svg("path", { class: "fill" });
        const t1 = svg("path", { class: "edge-line" });
        const t2 = svg("path", { class: "edge-line" });
        const dash = svg("path", { class: "edge-flow" });
        const tagG = svg("g");
        g.append(fill, t1, t2, dash, tagG);
        const row = svg("g", { class: "flow-row", "data-ip": h.ip || "" });
        const nameT = svg("text", { class: "fr-name" });
        const rateT = svg("text", { class: "fr-rate" });
        const shareT = svg("text", { class: "fr-share", "text-anchor": "end" });
        const track = svg("rect", { class: "fr-track", height: 2 });
        const barR = svg("rect", { class: "fr-bar", height: 2 });
        row.append(nameT, rateT, shareT, track, barR);
        this.flowsG.append(g, row);
        r = {
          g,
          fill,
          t1,
          t2,
          dash,
          tagG,
          row,
          nameT,
          rateT,
          shareT,
          track,
          barR,
        };
        this.flowItems.set(key, r);
      }
      const sev = sevClass(h.severity);
      r.g.setAttribute(
        "class",
        `ribbon${h.others ? " is-others" : ""}${sev ? ` is-${sev}` : ""}`,
      );
      r.row.setAttribute("class", `flow-row${sev ? ` is-${sev}` : ""}`);
      r.fill.setAttribute("d", it.path);
      r.t1.setAttribute("d", it.topLine);
      r.t2.setAttribute("d", it.botLine);
      r.dash.setAttribute("d", it.mid);
      const inc = hogs.get(h.ip);
      const hot = sev === "high" && !!inc;
      r.g.classList.toggle("is-hog", hot);
      r.dash.setAttribute("display", hot ? "inline" : "none");
      if (hot) {
        r.dash.style.setProperty("--gap", 14);
        r.dash.style.setProperty("--dur", "0.25s");
        r.dash.setAttribute("stroke-width", 2);
        r.fill.classList.add("breathe");
      } else r.fill.classList.remove("breathe");
      const vs = inc?.detail?.vs_normal;
      if (hot && inc) {
        const label =
          vs != null
            ? `+${Math.round(vs)}% vs normal`
            : truncate(inc.title, 20);
        const w = label.length * 6.6 + 18;
        const [mx, my] = it.midPoint;
        const tx = mx - w / 2,
          ty = my - 11;
        r.tagG.setAttribute("class", "callout-tag");
        r.tagG.replaceChildren(
          svg("path", {
            class: "tag-bg",
            d: `M${f(tx)} ${f(ty)}H${f(tx + w - 7)}L${f(tx + w)} ${f(ty + 7)}V${f(ty + 22)}H${f(tx)}Z`,
          }),
          svg("text", { class: "k", x: f(tx + 9), y: f(ty + 15), text: label }),
        );
      } else r.tagG.replaceChildren();
      const xr = x1 + 14;
      const right = W - 16;
      r.row.style.transform = `translate(0px, ${f(it.rowY)}px)`;
      r.nameT.setAttribute("x", xr);
      r.nameT.setAttribute("y", -3);
      r.nameT.textContent = truncate(h.name || h.ip, 26);
      r.rateT.setAttribute("x", xr);
      r.rateT.setAttribute("y", 11);
      r.rateT.textContent =
        sev && h.reason
          ? truncate(h.reason, 30)
          : `${fmtRate(h.bps)}${h.cc ? ` · ${h.cc}` : ""}`;
      r.shareT.setAttribute("x", right);
      r.shareT.setAttribute("y", 6);
      r.shareT.textContent = fmtPct(h.share);
      const trackW = Math.max(40, right - xr);
      r.track.setAttribute("x", xr);
      r.track.setAttribute("y", 15);
      r.track.setAttribute("width", trackW);
      r.barR.setAttribute("x", xr);
      r.barR.setAttribute("y", 15);
      r.barR.setAttribute(
        "width",
        Math.max(1, trackW * Math.min(1, h.share || 0)),
      );
    });

    // 60 s total-bandwidth strip with the spike band shaded.
    let strip = this.flowItems.get("strip");
    if (!strip) {
      strip = {
        g: svg("g"),
        spikes: svg("g"),
        area: svg("path", { class: "strip-area" }),
        a0: svg("text", { class: "strip-axis" }),
        a1: svg("text", { class: "strip-axis", "text-anchor": "end" }),
      };
      strip.g.append(strip.spikes, strip.area, strip.a0, strip.a1);
      this.flowsG.append(strip.g);
      this.flowItems.set("strip", strip);
    }
    wanted.add("strip");
    const tl = v.timeline || [];
    const sx0 = 56,
      sx1 = W - 16,
      sy0 = H - 52,
      sy1 = H - 14;
    const peak = Math.max(1, ...tl.map((p) => p[1]));
    const X = (i) => sx0 + (i / Math.max(1, tl.length - 1)) * (sx1 - sx0);
    const Y = (val) => sy1 - (val / peak) * (sy1 - sy0);
    if (tl.length) {
      let d = `M${f(X(0))} ${f(sy1)}`;
      tl.forEach((p, i) => {
        d += `L${f(X(i))} ${f(Y(p[1]))}`;
      });
      d += `L${f(X(tl.length - 1))} ${f(sy1)}Z`;
      strip.area.setAttribute("d", d);
      const base = v.baseline || 0;
      const spikeAt = (val) => base > 0 && val > Math.max(base * 2, 1e6);
      const bands = [];
      tl.forEach((p, i) => {
        if (spikeAt(p[1])) {
          const x = X(i) - (sx1 - sx0) / Math.max(1, tl.length - 1) / 2;
          const w = (sx1 - sx0) / Math.max(1, tl.length - 1);
          bands.push(
            svg("rect", {
              class: "strip-spike",
              x: f(x),
              y: sy0,
              width: f(w),
              height: sy1 - sy0,
            }),
          );
          bands.push(
            svg("line", {
              class: "strip-spike-top",
              x1: f(x),
              x2: f(x + w),
              y1: sy0,
              y2: sy0,
            }),
          );
        }
      });
      strip.spikes.replaceChildren(...bands);
    }
    strip.a0.setAttribute("x", sx0);
    strip.a0.setAttribute("y", H - 2);
    strip.a0.textContent = "−60 s";
    strip.a1.setAttribute("x", sx1);
    strip.a1.setAttribute("y", H - 2);
    strip.a1.textContent = `now · peak ${fmtRate(peak)}`;

    for (const [key, r] of this.flowItems) {
      if (!wanted.has(key)) {
        r.g.remove();
        r.row?.remove();
        this.flowItems.delete(key);
      }
    }
  }

  // -------------------------------------------------------------- incidents
  renderIncident() {
    const v = this.view;
    const list = v.incidents || [];
    const fresh = list.filter((i) => !this.knownIncidents.has(i.id));
    for (const i of list) this.knownIncidents.add(i.id);
    if (!list.length) {
      this.incident.className = "incident is-quiet";
      this.incident.replaceChildren(
        el("span", {
          text: `No active incidents · watching ${v.counts?.hosts ?? 0} hosts`,
        }),
      );
      return;
    }
    if (fresh.length && this.knownIncidents.size > list.length - fresh.length) {
      this.incidentIdx = list.indexOf(fresh[0]);
      if (this.tab === "map") this.sweep();
    }
    this.incidentIdx = Math.min(this.incidentIdx, list.length - 1);
    const inc = list[this.incidentIdx];
    const h = inc.host || {};
    const sev = sevClass(inc.severity) || "high";
    // Show the whole card when an incident first appears, then shrink it to its headline so it
    // stops covering the map. Hovering the card brings the details back.
    if (!this.incSeen.has(inc.id)) this.incSeen.set(inc.id, Date.now());
    const compact = !fresh.length && Date.now() - this.incSeen.get(inc.id) > 6000;
    this.incident.className = `incident hud-notch sev-${sev === "high" ? "high" : "medium"}${compact ? " is-compact" : ""}${fresh.length ? " flash" : ""}`;
    const nums = [];
    const liveShare =
      v.total_bps > 0 && h.bps != null ? h.bps / v.total_bps : null;
    if (inc.kind === "bandwidth_hog" && inc.detail) {
      nums.push(["red", fmtRate(h.bps ?? inc.detail.bps), "now"]);
      nums.push(["", fmtPct(liveShare ?? inc.detail.share), "of traffic"]);
      if (inc.detail.vs_normal != null)
        nums.push(["", `+${Math.round(inc.detail.vs_normal)}%`, "vs normal"]);
    } else if (inc.kind === "port_scan" && inc.detail) {
      nums.push(["red", String(inc.detail.ports), "ports probed"]);
      const target =
        inc.detail.target === v.self?.ip ? "This Mac" : inc.detail.target || "";
      nums.push(["", truncate(target, 15), "target"]);
    } else if (inc.kind === "cleartext_credentials" && inc.detail) {
      nums.push(["red", truncate(inc.detail.field || "secret", 10), "field"]);
      nums.push(["", "none", "encryption"]);
    } else {
      nums.push(["red", fmtRate(h.bps || 0), "now"]);
      nums.push(["", String(h.packets ?? "—"), "packets"]);
    }
    const hostLine = [h.ip || inc.hosts?.[0], h.name, h.cc]
      .filter(Boolean)
      .join(" · ");
    const age = (v.now || Date.now() / 1000) - inc.ts;
    const showReason = !["bandwidth_hog", "port_scan"].includes(inc.kind);
    this.incident.replaceChildren(
      el(
        "div",
        { class: "row1" },
        el("span", {
          class: `sev sev-${inc.severity}`,
          text: inc.severity.toUpperCase(),
        }),
        el("span", { class: "ttl", text: inc.title.toUpperCase() }),
        el(
          "span",
          { class: "pager" },
          el("span", { text: `${this.incidentIdx + 1}/${list.length}` }),
          list.length > 1
            ? el(
                "button",
                {
                  type: "button",
                  "aria-label": "Next incident",
                  "data-next": "1",
                },
                icon("chevron-right"),
              )
            : null,
        ),
      ),
      el("div", { class: "host", text: hostLine, title: hostLine }),
      el(
        "div",
        { class: "nums" },
        ...nums.map(([c, n, l]) =>
          el(
            "div",
            { class: c },
            el("b", { text: n }),
            el("span", { text: l }),
          ),
        ),
      ),
      alertInfo(inc.kind)
        ? el("div", { class: "means", text: alertInfo(inc.kind).means })
        : null,
      el("div", {
        class: "foot",
        text: `${showReason ? `${inc.reason} · ` : ""}since ${clock(inc.ts)} (${ago(age)}) · click to filter`,
      }),
    );
    if (fresh.length)
      setTimeout(() => this.incident.classList.remove("flash"), 700);
  }

  onIncidentClick(ev) {
    const list = this.view?.incidents || [];
    if (!list.length) return;
    if (ev.target.closest("[data-next]")) {
      ev.stopPropagation();
      this.incidentIdx = (this.incidentIdx + 1) % list.length;
      this.renderIncident();
      return;
    }
    const ip = list[this.incidentIdx]?.hosts?.[0];
    if (ip) this.onSelect(ip);
  }

  // ------------------------------------------------------------ interaction
  keyFromEvent(ev) {
    const node = ev.target.closest?.(".node, .ribbon, .flow-row");
    if (!node) return null;
    if (node.classList.contains("node"))
      return { key: node.dataset.key, ip: node.dataset.ip };
    return { key: `ip:${node.dataset.ip}`, ip: node.dataset.ip };
  }

  onHover(ev) {
    const k = this.keyFromEvent(ev);
    this.setHover(k);
  }

  setHover(k) {
    const key = k?.key || null;
    if (key === this.hoverKey) return;
    this.hoverKey = key;
    this.hoverIp = k?.ip || null;
    this.applyHover();
  }

  applyHover() {
    const root = this.svg;
    root
      .querySelectorAll(".is-related")
      .forEach((n) => n.classList.remove("is-related"));
    root
      .querySelectorAll(".edge.is-path")
      .forEach((n) => n.classList.remove("is-path"));
    if (!this.hoverKey || !this.view) {
      root.classList.remove("nv-dim");
      this.hovercard.classList.remove("is-on");
      return;
    }
    if (this.tab === "map") {
      const n = this.nodes.get(this.hoverKey);
      if (!n) {
        root.classList.remove("nv-dim");
        return;
      }
      root.classList.add("nv-dim");
      for (const k of [this.hoverKey, "self", "gw"])
        this.nodes.get(k)?.g.classList.add("is-related");
      for (const k of [`e:${this.hoverKey}`, "trunk"]) {
        const e = this.edges.get(k);
        if (e) {
          e.g.classList.add("is-related", "is-path");
        }
      }
      this.showCard(n.item);
    } else {
      root.classList.add("nv-dim");
      root
        .querySelectorAll(
          `.ribbon[data-ip="${CSS.escape(this.hoverIp || "")}"], .flow-row[data-ip="${CSS.escape(this.hoverIp || "")}"]`,
        )
        .forEach((x) => x.classList.add("is-related"));
      const h = [...(this.view.internet || []), ...(this.view.lan || [])].find(
        (x) => x.ip === this.hoverIp,
      );
      if (h) {
        const row = this.svg.querySelector(
          `.flow-row[data-ip="${CSS.escape(h.ip)}"]`,
        );
        const y = row
          ? parseFloat(
              (row.style.transform.match(/,\s*([\d.]+)px/) || [])[1] || 0,
            )
          : this.H / 2;
        this.showCard({ host: h, pos: [this.W - 280, y], zone: "flows" });
      } else this.hovercard.classList.remove("is-on");
    }
  }

  showCard(it) {
    const h = it.host || {};
    if (!h.ip && !it.others) {
      this.hovercard.classList.remove("is-on");
      return;
    }
    const name =
      it.key === "self"
        ? "This Mac"
        : it.key === "gw"
          ? "Gateway"
          : h.name || h.ip;
    const where = [KIND_LABEL[h.kind] || "", h.city, h.country]
      .filter(Boolean)
      .join(" · ");
    const grid = el(
      "div",
      { class: "hc-grid" },
      el("span", { text: "Rate" }),
      el("b", { text: fmtRate(h.bps) }),
      el("span", { text: "Share 60 s" }),
      el("b", { text: fmtPct(h.share) }),
      el("span", { text: "Packets" }),
      el("b", { text: String(h.packets ?? "—") }),
      el("span", { text: "First seen" }),
      el("b", {
        text: h.first ? `${ago((this.view.now || 0) - h.first)} ago` : "—",
      }),
    );
    const spark = svg("svg", {
      viewBox: "0 0 216 28",
      preserveAspectRatio: "none",
    });
    const s = h.spark || [];
    if (s.length > 1) {
      const max = Math.max(1, ...s);
      const pts = s.map(
        (val, i) =>
          `${f((i / (s.length - 1)) * 214 + 1)},${f(26 - (val / max) * 24)}`,
      );
      const color = sevClass(h.severity) === "high" ? "#ff003c" : "#00ff41";
      spark.append(
        svg("polyline", {
          points: pts.join(" "),
          fill: "none",
          stroke: color,
          "stroke-width": 1,
        }),
      );
      const last = pts[pts.length - 1].split(",");
      spark.append(
        svg("circle", { cx: last[0], cy: last[1], r: 2, fill: color }),
      );
    }
    const kids = [
      el("div", { class: "hc-name", text: name }),
      el("div", {
        class: "hc-ip",
        text: [h.ip, where].filter(Boolean).join(" · "),
      }),
      grid,
      spark,
    ];
    if (h.reason)
      kids.push(
        el("div", { class: "hc-reason", text: `${h.title}: ${h.reason}` }),
      );
    if (h.ip)
      kids.push(el("div", { class: "hc-foot", text: `click → ip == ${h.ip}` }));
    this.hovercard.replaceChildren(...kids);
    const [x, y] = it.pos || [0, 0];
    const left = it.zone === "column" || x + 260 > this.W ? x - 256 : x + 28;
    const top = Math.max(8, Math.min(this.H - 190, y - 70));
    this.hovercard.style.left = `${Math.max(8, left)}px`;
    this.hovercard.style.top = `${top}px`;
    this.hovercard.classList.add("is-on");
  }

  onClick(ev) {
    const k = this.keyFromEvent(ev);
    if (!k || !k.ip) return;
    const ip = k.ip === this.selected ? null : k.ip;
    this.onSelect(ip);
  }
}
