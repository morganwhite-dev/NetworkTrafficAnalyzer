// Number and time formatting. Always 3 significant figures so readouts don't jitter.

export function sig3(n) {
  if (!Number.isFinite(n)) return "0";
  if (n === 0) return "0";
  const abs = Math.abs(n);
  if (abs >= 100) return Math.round(n).toString();
  if (abs >= 10) return n.toFixed(1);
  return n.toFixed(2);
}

export function fmtRate(bps) {
  if (!bps || bps < 1) return "0 B/s";
  if (bps >= 1e9) return `${sig3(bps / 1e9)} GB/s`;
  if (bps >= 1e6) return `${sig3(bps / 1e6)} MB/s`;
  if (bps >= 1e3) return `${sig3(bps / 1e3)} KB/s`;
  return `${Math.round(bps)} B/s`;
}

export function fmtBytes(b) {
  if (!b) return "0 B";
  if (b >= 1e9) return `${sig3(b / 1e9)} GB`;
  if (b >= 1e6) return `${sig3(b / 1e6)} MB`;
  if (b >= 1e3) return `${sig3(b / 1e3)} KB`;
  return `${Math.round(b)} B`;
}

export function fmtCount(n) {
  if (n >= 1e6) return `${sig3(n / 1e6)}M`;
  if (n >= 1e4) return `${sig3(n / 1e3)}k`;
  return String(Math.round(n));
}

export function fmtPct(share) {
  return `${Math.round((share || 0) * 100)}%`;
}

export function clock(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

export function ago(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  return `${Math.floor(s / 3600)} h`;
}

export function truncate(s, n) {
  const str = String(s ?? "");
  return str.length > n ? `${str.slice(0, n - 1)}…` : str;
}

/** createElement helper. Text goes through textContent only (never innerHTML). */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function")
      node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const SVGNS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.setAttribute("class", v);
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, String(v));
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

export function icon(name, cls = "icon") {
  const s = svg("svg", { class: cls, "aria-hidden": "true" });
  const use = document.createElementNS(SVGNS, "use");
  use.setAttribute("href", `/static/vendor/icons.svg#i-${name}`);
  s.append(use);
  return s;
}
