import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ALERT_INFO, alertInfo, PANEL_TIPS, plainSummary, PROTO_TIPS, protoTip, SEVERITY_TIPS,
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
  for (const p of ["network", "alerts", "bandwidth", "protocols", "geo", "packets", "inspector"]) {
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
