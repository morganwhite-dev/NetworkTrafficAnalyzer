// One tooltip for the whole dashboard. Any element with data-tip="…" gets it,
// including ones created later (alert rows, protocol rows, table headers).
// Hover or keyboard focus shows it; Esc or leaving hides it. The text goes in
// through textContent only.

let tip = null;
let owner = null;

function ensure() {
  if (tip) return tip;
  tip = document.createElement("div");
  tip.className = "tip";
  tip.setAttribute("role", "tooltip");
  tip.id = "tip";
  tip.hidden = true;
  document.body.append(tip);
  return tip;
}

function show(target) {
  const text = target.getAttribute("data-tip");
  if (!text) return;
  const t = ensure();
  owner = target;
  t.textContent = text;
  t.hidden = false;
  target.setAttribute("aria-describedby", "tip");
  const r = target.getBoundingClientRect();
  const tw = t.offsetWidth;
  const th = t.offsetHeight;
  const margin = 8;
  let x = r.left + r.width / 2 - tw / 2;
  let y = r.bottom + 8;
  if (target.getAttribute("data-tip-side") === "right") {
    // Beside the element (menu items), so it doesn't cover the item below.
    x = r.right + 10;
    y = r.top + r.height / 2 - th / 2;
  }
  x = Math.max(margin, Math.min(x, window.innerWidth - tw - margin));
  // Below the element, or above it when there isn't room.
  if (y + th > window.innerHeight - margin)
    y = Math.max(margin, r.top - th - 8);
  y = Math.max(margin, y);
  t.style.left = `${Math.round(x)}px`;
  t.style.top = `${Math.round(y)}px`;
}

function hide() {
  if (!tip) return;
  tip.hidden = true;
  owner?.removeAttribute("aria-describedby");
  owner = null;
}

export function initTooltips() {
  const find = (ev) => ev.target.closest?.("[data-tip]");
  document.addEventListener("mouseover", (ev) => {
    const el = find(ev);
    if (el && el !== owner) show(el);
    else if (!el) hide();
  });
  document.addEventListener("mouseout", (ev) => {
    if (!ev.relatedTarget || !find({ target: ev.relatedTarget })) hide();
  });
  document.addEventListener("focusin", (ev) => {
    const el = find(ev);
    if (el) show(el);
  });
  document.addEventListener("focusout", hide);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") hide();
  });
  // Hide when the thing the tip belongs to scrolls away. A table that scrolls itself as
  // packets arrive must not kill a tip that belongs to something else.
  document.addEventListener(
    "scroll",
    (ev) => {
      const t = ev.target;
      if (t === document || (owner && t.contains?.(owner))) hide();
    },
    true,
  );
  // Panels rebuild their rows every second. If the element under the pointer was replaced,
  // move the tip to its replacement, or drop it when the pointer is over nothing.
  let px = -1;
  let py = -1;
  document.addEventListener("mousemove", (ev) => {
    px = ev.clientX;
    py = ev.clientY;
  });
  setInterval(() => {
    if (!owner || owner.isConnected || px < 0) return;
    const next = document.elementFromPoint(px, py)?.closest?.("[data-tip]");
    if (next) show(next);
    else hide();
  }, 300);
  document.addEventListener("click", (ev) => {
    // Touch: a tap shows it, a tap elsewhere hides it.
    if (!find(ev)) hide();
  });
}
