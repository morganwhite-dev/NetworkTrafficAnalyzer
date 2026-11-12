import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ALERT_INFO, alertInfo, alertNumbers, PANEL_TIPS, plainSummary, PROTO_TIPS, protoTip, SEVERITY_TIPS,
} from "../js/glossary.js";

// Every `kind` the detectors can raise (backend/app/detectors.py).
const KINDS = [
  "port_scan", "host_sweep", "cleartext_credentials", "cleartext_session", "traffic_spike",
  "bandwidth_hog", "arp_spoof", "mac_change", "dns_tunnel", "rogue_dhcp", "rogue_ra", "vpn_leak",
];

test("every alert kind explains what it means and what to do", () => {
  for (const k of KINDS) {
    const info = alertInfo(k);
    assert.ok(info, `missing explainer for ${k}`);
    assert.ok(info.means.length > 20 && info.todo.length > 10, k);
  }
  assert.equal(alertInfo("nope"), null);
  assert.deepEqual(Object.keys(ALERT_INFO).sort(), [...KINDS].sort());
});

test("every protocol the donut can show has a plain-English tip", () => {
  for (const p of ["TLS", "QUIC", "TCP", "UDP", "DNS", "HTTP", "ICMP", "ARP", "Other"]) {
    assert.ok(PROTO_TIPS[p], p);
  }
  assert.equal(protoTip("???"), "");
});

test("every severity and panel has help text", () => {
  for (const s of ["critical", "high", "medium", "low", "info"]) assert.ok(SEVERITY_TIPS[s], s);
  for (const p of ["network", "alerts", "traffic", "packets", "inspector"]) {
    assert.ok(PANEL_TIPS[p], p);
  }
});

test("plain summary names the endpoints and the kind of traffic", () => {
  const names = { "10.0.0.2": "This Mac", "93.184.215.14": "zoom.us" };
  const out = plainSummary({ proto: "TLS", src: "10.0.0.2", dst: "93.184.215.14" }, (ip) => names[ip] ?? ip);
  assert.equal(out, "This Mac sent encrypted web traffic to zoom.us.");
  assert.equal(
    plainSummary({ proto: "XYZ", src: "a", dst: "b" }),
    "a sent XYZ traffic to b.",
  );
});

test("alert numbers come from the alert's own detail", () => {
  const name = (ip) => (ip === "10.0.0.2" ? "This Mac" : ip);
  const hog = alertNumbers(
    { kind: "bandwidth_hog", detail: { bps: 5_890_000, share: 0.91, vs_normal: 1142 } },
  );
  assert.deepEqual(hog.map((n) => n.label), ["now", "of traffic", "vs normal"]);
  assert.equal(hog[0].value, "5.89 MB/s");
  assert.equal(hog[1].value, "91%");
  assert.equal(hog[2].value, "+1142%");
  const scan = alertNumbers({ kind: "port_scan", detail: { ports: 214, target: "10.0.0.2" } }, name);
  assert.deepEqual(scan.map((n) => n.value), ["214", "This Mac"]);
  const creds = alertNumbers({ kind: "cleartext_credentials", detail: { field: "password" } });
  assert.deepEqual(creds.map((n) => n.value), ["password", "none"]);
  assert.deepEqual(alertNumbers({ kind: "mac_change", detail: {} }), []);
  assert.deepEqual(alertNumbers({ kind: "bandwidth_hog" }), []);
});
