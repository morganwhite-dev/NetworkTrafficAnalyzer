// Packet inspector: decoded layers as a tree plus a Hex/ASCII dump.

import { get } from "./api.js";
import { el, icon } from "./format.js";

export class Inspector {
  constructor({ root, body, toggle }) {
    this.root = root;
    this.body = body;
    this.toggleBtn = toggle;
    this.current = null;
    toggle.addEventListener("click", () =>
      this.setCollapsed(!root.classList.contains("is-collapsed")),
    );
  }

  setCollapsed(on) {
    this.root.classList.toggle("is-collapsed", on);
    this.toggleBtn.setAttribute(
      "aria-label",
      on ? "Expand inspector" : "Collapse inspector",
    );
    this.toggleBtn.replaceChildren(
      icon(
        on ? "layout-sidebar-right-expand" : "layout-sidebar-right-collapse",
      ),
    );
  }

  clear() {
    this.current = null;
    this.body.replaceChildren(
      el("div", {
        class: "empty",
        text: "Click a packet to see its decoded headers and a hex dump.",
      }),
    );
  }

  async show(id) {
    this.current = id;
    if (this.root.classList.contains("is-collapsed")) this.setCollapsed(false);
    let data;
    try {
      data = await get(`/api/packets/${id}`);
    } catch (err) {
      if (this.current === id) {
        this.body.replaceChildren(
          el("div", { class: "empty", text: err.message }),
        );
      }
      return;
    }
    if (this.current !== id) return;
    this.render(data);
  }

  render(d) {
    const bytes = hexToBytes(d.hex);
    const layerOf = new Uint8Array(bytes.length);
    const ranges = (d.layers || []).map((l) => [l.start, l.end]);
    // Tint: 0 = link, 1 = network, 2 = transport, 3 = payload (everything after the last header).
    const lastHeaderEnd = ranges.length
      ? Math.max(...ranges.map((r) => r[1]))
      : 0;
    ranges.forEach(([s, e], i) => {
      const tint = Math.min(i, 2);
      for (let k = s; k < Math.min(e, bytes.length); k++) layerOf[k] = tint;
    });
    for (let k = lastHeaderEnd; k < bytes.length; k++) layerOf[k] = 3;
    const secret = new Uint8Array(bytes.length);
    for (const [s, e] of d.secrets || [])
      for (let k = s; k < Math.min(e, bytes.length); k++) secret[k] = 1;

    const r = d.row;
    const summary = el(
      "div",
      { class: "insp-summary" },
      el("div", { class: `proto p-${r.proto}`, text: `#${d.id} · ${r.proto}` }),
      el("div", {
        class: "meta",
        text: `${r.src}${r.sport != null ? `:${r.sport}` : ""} → ${r.dst}${r.dport != null ? `:${r.dport}` : ""}`,
      }),
      el("div", {
        class: "meta",
        text: `${r.len} bytes on the wire · ${d.caplen} captured · ${new Date(d.ts * 1000).toLocaleTimeString([], { hour12: false })}`,
      }),
      el("div", { class: "meta", text: r.info }),
    );

    const tree = el("div", { class: "layers" });
    (d.layers || []).forEach((layer, i) => {
      const wrap = el("div", {
        class: `layer${i === (d.layers.length > 1 ? d.layers.length - 1 : 0) ? " is-open" : ""}`,
      });
      const btn = el(
        "button",
        {
          type: "button",
          "aria-expanded": wrap.classList.contains("is-open")
            ? "true"
            : "false",
        },
        icon("chevron-right", "icon chev"),
        el("span", { text: layer.name }),
        el("span", { class: "range", text: `${layer.start}–${layer.end}` }),
      );
      btn.addEventListener("click", () => {
        wrap.classList.toggle("is-open");
        btn.setAttribute(
          "aria-expanded",
          wrap.classList.contains("is-open") ? "true" : "false",
        );
      });
      btn.addEventListener("mouseenter", () =>
        this.highlightRange(layer.start, layer.end, "fl"),
      );
      btn.addEventListener("mouseleave", () => this.highlightRange(0, 0, "fl"));
      const fields = el(
        "div",
        { class: "fields" },
        ...layer.fields.map((f) =>
          el(
            "div",
            { class: "field" },
            el("span", { class: "k", text: f.name }),
            el("span", { class: "v", text: f.value }),
          ),
        ),
      );
      wrap.append(btn, fields);
      tree.append(wrap);
    });

    const hex = el("div", {
      class: "hex",
      role: "img",
      "aria-label": "Hex and ASCII dump",
    });
    this.cells = [];
    for (let off = 0; off < bytes.length; off += 16) {
      const hexCol = el("div", { class: "bytes" });
      const asciiCol = el("div", { class: "ascii" });
      for (let k = off; k < Math.min(off + 16, bytes.length); k++) {
        const b = bytes[k];
        const tint = `L${layerOf[k]}`;
        const h = el("span", {
          class: `${tint}${b === 0 ? " z" : ""}${k % 16 === 7 ? " gap" : ""}${secret[k] ? " secret" : ""}`,
          "data-i": k,
          text: b.toString(16).padStart(2, "0"),
        });
        const printable = b >= 0x20 && b < 0x7f;
        const a = el("span", {
          class: `${printable ? tint : "np"}${secret[k] ? " secret" : ""}`,
          "data-i": k,
          text: printable ? String.fromCharCode(b) : "·",
        });
        hexCol.append(h);
        asciiCol.append(a);
        this.cells[k] = [h, a];
      }
      hex.append(
        el("div", { class: "off", text: off.toString(16).padStart(4, "0") }),
        hexCol,
        asciiCol,
      );
    }
    hex.addEventListener("mouseover", (ev) => {
      const i = ev.target?.dataset?.i;
      if (i !== undefined) this.highlightRange(Number(i), Number(i) + 1, "hl");
    });
    hex.addEventListener("mouseleave", () => this.highlightRange(0, 0, "hl"));
    hex.addEventListener("click", (ev) => {
      if (ev.target.classList.contains("secret"))
        hex.classList.toggle("revealed");
    });

    const notes = [];
    if ((d.secrets || []).length)
      notes.push(
        el("div", {
          class: "insp-note warn",
          text: "Contains cleartext credentials. They're blurred; click them to reveal.",
        }),
      );
    if (d.caplen < r.len)
      notes.push(
        el("div", {
          class: "insp-note",
          text: `Only the first ${d.caplen} of ${r.len} bytes were captured.`,
        }),
      );
    if (d.truncated)
      notes.push(
        el("div", {
          class: "insp-note",
          text: "Dump truncated to the first 64 KB.",
        }),
      );

    this.body.replaceChildren(summary, tree, ...notes, hex);
  }

  highlightRange(start, end, cls) {
    if (!this.cells) return;
    for (const pair of this.cells) {
      if (!pair) continue;
      pair[0].classList.remove(cls);
      pair[1].classList.remove(cls);
    }
    for (let k = start; k < end; k++) {
      const pair = this.cells[k];
      if (!pair) continue;
      pair[0].classList.add(cls);
      pair[1].classList.add(cls);
    }
  }
}

function hexToBytes(hex) {
  const out = new Uint8Array((hex || "").length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
