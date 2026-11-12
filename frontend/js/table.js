// Virtualized packet table: fixed 24px rows, only the visible window is in the DOM.

import { el } from "./format.js";
import { protoTip } from "./glossary.js";

const ROW = 24;
const OVERSCAN = 12;
const MAX_ROWS = 10000;

export class PacketTable {
  constructor({ scroll, spacer, jump, jumpText, stat, onSelect, labelFor }) {
    this.labelFor = labelFor || ((ip) => ip);
    this.scroll = scroll;
    this.spacer = spacer;
    this.jump = jump;
    this.jumpText = jumpText;
    this.stat = stat;
    this.onSelect = onSelect;
    this.all = []; // every row we hold (capped)
    this.view = []; // rows matching the filter
    this.filter = null;
    this.flagged = new Set();
    this.selected = null;
    this.follow = true;
    this.unseen = 0;
    this.baseTs = null;
    this.pool = new Map(); // index -> element
    this.raf = 0;
    scroll.addEventListener("scroll", () => {
      const atBottom =
        scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - ROW;
      if (atBottom) {
        this.follow = true;
        this.unseen = 0;
      } else if (this.programmatic) {
        /* ignore our own scroll */
      } else this.follow = false;
      this.programmatic = false;
      this.updateJump();
      this.schedule();
    });
    jump.addEventListener("click", () => this.toBottom());
    scroll.addEventListener("click", (ev) => {
      const row = ev.target.closest(".prow");
      if (row) this.select(Number(row.dataset.id));
    });
    scroll.addEventListener("keydown", (ev) => this.onKey(ev));
    scroll.tabIndex = 0;
    new ResizeObserver(() => this.schedule()).observe(scroll);
  }

  reset(rows) {
    this.all = rows.slice(-MAX_ROWS);
    this.baseTs = this.all.length ? this.all[0].t : null;
    this.recompute();
    this.toBottom();
  }

  append(rows) {
    if (!rows.length) return;
    if (this.baseTs === null) this.baseTs = rows[0].t;
    this.all.push(...rows);
    let dropped = 0;
    if (this.all.length > MAX_ROWS) {
      dropped = this.all.length - MAX_ROWS;
      this.all.splice(0, dropped);
    }
    const matched = this.filter ? rows.filter(this.filter) : rows;
    this.view.push(...matched);
    if (dropped) {
      const firstId = this.all[0].id;
      let cut = 0;
      while (cut < this.view.length && this.view[cut].id < firstId) cut++;
      if (cut) {
        this.view.splice(0, cut);
        if (!this.follow)
          this.scroll.scrollTop = Math.max(
            0,
            this.scroll.scrollTop - cut * ROW,
          );
      }
    }
    if (!this.follow) this.unseen += matched.length;
    this.layout();
    if (this.follow) this.toBottom(true);
    this.updateJump();
  }

  setFilter(pred) {
    this.filter = pred;
    this.recompute();
    this.toBottom();
  }

  setFlagged(set) {
    const changed =
      set.size !== this.flagged.size ||
      [...set].some((x) => !this.flagged.has(x));
    this.flagged = set;
    if (changed) this.repaint();
  }

  recompute() {
    this.view = this.filter ? this.all.filter(this.filter) : this.all.slice();
    this.layout();
    this.repaint();
  }

  layout() {
    this.spacer.style.height = `${this.view.length * ROW}px`;
    const total = this.all.length;
    this.stat.textContent = this.filter
      ? `${this.view.length.toLocaleString()} OF ${total.toLocaleString()}`
      : `${total.toLocaleString()} PACKETS`;
    this.onStat?.(this.stat.textContent);
    this.schedule();
  }

  toBottom(soft = false) {
    this.follow = true;
    this.unseen = 0;
    this.programmatic = true;
    this.scroll.scrollTop = this.scroll.scrollHeight;
    if (!soft) this.updateJump();
    this.schedule();
  }

  updateJump() {
    const show = !this.follow && this.view.length > 0;
    this.jump.hidden = !show;
    this.jumpText.textContent = this.unseen
      ? `JUMP TO LIVE · ${this.unseen > 999 ? "999+" : this.unseen} NEW`
      : "JUMP TO LIVE";
  }

  schedule() {
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.render();
    });
  }

  repaint() {
    for (const node of this.pool.values()) node.remove();
    this.pool.clear();
    this.schedule();
  }

  render() {
    const top = this.scroll.scrollTop;
    const height = this.scroll.clientHeight || 400;
    const first = Math.max(0, Math.floor(top / ROW) - OVERSCAN);
    const last = Math.min(
      this.view.length,
      Math.ceil((top + height) / ROW) + OVERSCAN,
    );
    for (const [idx, node] of this.pool) {
      if (
        idx < first ||
        idx >= last ||
        node.dataset.id !== String(this.view[idx]?.id)
      ) {
        node.remove();
        this.pool.delete(idx);
      }
    }
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      if (this.pool.has(i)) continue;
      const node = this.rowEl(this.view[i], i);
      this.pool.set(i, node);
      frag.append(node);
    }
    this.spacer.append(frag);
  }

  rowEl(r, idx) {
    const flagged = this.flagged.has(r.src) || this.flagged.has(r.dst);
    const cls = [
      "prow",
      flagged && "is-flagged",
      r.id === this.selected && "is-selected",
    ]
      .filter(Boolean)
      .join(" ");
    const rel = this.baseTs !== null ? (r.t - this.baseTs).toFixed(3) : "";
    // Show the names the map uses; the raw address stays in the hover text.
    const raw = (ip, port) => (port != null ? `${ip}:${port}` : ip);
    const show = (ip, port) => {
      const name = this.labelFor(ip);
      return port != null ? `${name}:${port}` : name;
    };
    const src = show(r.src, r.sport);
    const dst = show(r.dst, r.dport);
    const srcRaw = raw(r.src, r.sport);
    const dstRaw = raw(r.dst, r.dport);
    const node = el(
      "div",
      { class: cls, role: "row", "data-id": r.id },
      el("span", { class: "t", text: rel }),
      el("span", { class: "src", text: src, title: srcRaw }),
      el("span", { class: "dst", text: dst, title: dstRaw }),
      el("span", {
        class: `p-${r.proto}`,
        text: r.proto,
        "data-tip": protoTip(r.proto),
      }),
      el("span", { class: "r num", text: r.len }),
      el("span", { class: "info", text: r.info, title: r.info }),
    );
    node.style.transform = `translateY(${idx * ROW}px)`;
    return node;
  }

  select(id) {
    this.selected = id;
    for (const node of this.pool.values()) {
      node.classList.toggle("is-selected", Number(node.dataset.id) === id);
    }
    this.onSelect(id);
  }

  onKey(ev) {
    if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
    ev.preventDefault();
    let idx = this.view.findIndex((r) => r.id === this.selected);
    idx =
      ev.key === "ArrowDown"
        ? Math.min(this.view.length - 1, idx + 1)
        : Math.max(0, idx - 1);
    if (idx < 0 || !this.view[idx]) return;
    this.follow = false;
    const y = idx * ROW;
    if (y < this.scroll.scrollTop) this.scroll.scrollTop = y;
    else if (y + ROW > this.scroll.scrollTop + this.scroll.clientHeight) {
      this.scroll.scrollTop = y + ROW - this.scroll.clientHeight;
    }
    this.select(this.view[idx].id);
  }
}
