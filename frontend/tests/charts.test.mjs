import assert from "node:assert/strict";
import { test } from "node:test";

import { protoShares } from "../js/charts.js";

test("protocol shares are ranked and rounded for display", () => {
  const { total, items } = protoShares({ TLS: 590, TCP: 390, DNS: 9, UDP: 1, ICMP: 0 });
  assert.equal(total, 990);
  assert.deepEqual(items.map((i) => i.name), ["TLS", "TCP", "DNS", "UDP"]);
  assert.deepEqual(items.map((i) => i.label), ["60%", "39%", "<1%", "<1%"]);
  assert.deepEqual(items.map((i) => i.faint), [false, false, true, true]);
  assert.ok(items.every((i) => i.color));
});

test("no traffic gives an empty bar", () => {
  assert.deepEqual(protoShares({}), { total: 0, items: [] });
});
