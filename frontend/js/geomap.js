// Geo-IP world map (Leaflet, vendored). Popups are DOM nodes, never HTML strings.

import { el } from "./format.js";

export class GeoMap {
  constructor({ container, stat, note, onSelect, onArrive }) {
    const L = window.L;
    this.L = L;
    this.stat = stat;
    this.note = note;
    this.onSelect = onSelect;
    this.onArrive = onArrive;
    this.map = L.map(container, {
      worldCopyJump: true,
      zoomControl: false,
      attributionControl: true,
      minZoom: 1,
      maxZoom: 8,
      zoomSnap: 0.25,
    }).setView([25, 5], 1.25);
    // Offline world outline (Natural Earth, public domain): no tile servers, no API keys,
    // and nothing about where you're looking leaves this Mac.
    this.map.attributionControl.setPrefix(false);
    this.map.attributionControl.addAttribution("Natural Earth · DB-IP.com");
    fetch("/static/vendor/world-110m.geojson")
      .then((r) => r.json())
      .then((world) => {
        L.geoJSON(world, {
          interactive: false,
          style: { color: "#2a3342", weight: 0.6, fillColor: "#151a23", fillOpacity: 1 },
        }).addTo(this.map).bringToBack();
      })
      .catch(() => { this.note.textContent = "World outline failed to load."; });
    this.markers = new Map(); // "lat,lon" -> { marker, ips:Set }
    this.seen = new Set();
    this.selected = null;
    new ResizeObserver(() => this.map.invalidateSize()).observe(container);
  }

  setProvider(provider, hint) {
    this.provider = provider;
    if (provider === "off") {
      this.note.textContent =
        "Geo-IP is off. Run scripts/download_geoip.sh for offline lookups.";
    } else {
      this.note.textContent = "";
    }
    if (hint && provider === "off") this.note.title = hint;
  }

  reset() {
    for (const { marker } of this.markers.values()) marker.remove();
    this.markers.clear();
    this.seen.clear();
    this.stat.textContent = "";
  }

  update(items) {
    const groups = new Map();
    for (const it of items) {
      const key = `${it.lat.toFixed(1)},${it.lon.toFixed(1)}`;
      let g = groups.get(key);
      if (!g) {
        g = { lat: it.lat, lon: it.lon, items: [], packets: 0, flagged: false };
        groups.set(key, g);
      }
      g.items.push(it);
      g.packets += it.packets;
      if (it.severity === "high" || it.severity === "critical")
        g.flagged = true;
    }
    for (const [key, entry] of this.markers) {
      if (!groups.has(key)) {
        entry.marker.remove();
        this.markers.delete(key);
      }
    }
    let arrived = false;
    for (const [key, g] of groups) {
      const radius = Math.min(
        10,
        3 + (2 * Math.log2(Math.max(1, g.packets))) / 3,
      );
      const style = {
        radius,
        weight: 0,
        fillOpacity: 0.55,
        fillColor: g.flagged ? "#ff003c" : "#00ff41",
        color: "#00f3ff",
      };
      let entry = this.markers.get(key);
      if (!entry) {
        const marker = this.L.circleMarker([g.lat, g.lon], style).addTo(
          this.map,
        );
        marker.on("click", () => this.onSelect?.(marker._nta?.items?.[0]?.ip));
        entry = { marker };
        this.markers.set(key, entry);
        if (!this.seen.has(key)) {
          this.seen.add(key);
          this.ring(g.lat, g.lon, g.flagged);
          arrived = true;
        }
      } else {
        entry.marker.setStyle(style);
        entry.marker.setRadius(radius);
      }
      entry.marker._nta = g;
      const selected = g.items.some((i) => i.ip === this.selected);
      entry.marker.setStyle({ weight: selected ? 1.5 : 0 });
      entry.marker.bindPopup(() => this.popup(g), {
        closeButton: false,
        autoPan: false,
      });
    }
    if (arrived) this.onArrive?.();
    const countries = new Set(items.map((i) => i.cc).filter(Boolean));
    this.stat.textContent = items.length
      ? `${items.length} HOSTS · ${countries.size} COUNTRIES`
      : "";
  }

  popup(g) {
    const first = g.items[0];
    const place = [first.city, first.country].filter(Boolean).join(", ");
    const box = el(
      "div",
      { class: "geo-popup" },
      el("div", { class: "name", text: place || "Unknown location" }),
    );
    for (const it of g.items.slice(0, 5)) {
      box.append(
        el("div", {
          class: "meta",
          text: `${it.name || it.ip} · ${it.packets} pkts${it.org ? ` · ${it.org}` : ""}`,
        }),
      );
    }
    if (g.items.length > 5)
      box.append(
        el("div", { class: "meta", text: `+${g.items.length - 5} more` }),
      );
    return box;
  }

  ring(lat, lon, red) {
    const icon = this.L.divIcon({
      className: "",
      html: "",
      iconSize: [20, 20],
    });
    const m = this.L.marker([lat, lon], {
      icon,
      interactive: false,
      keyboard: false,
    }).addTo(this.map);
    const node = m.getElement();
    if (node) {
      const ring = el("div", { class: `arrival-ring${red ? " red" : ""}` });
      node.append(ring);
    }
    setTimeout(() => m.remove(), 1300);
  }

  select(ip) {
    this.selected = ip;
  }
}
