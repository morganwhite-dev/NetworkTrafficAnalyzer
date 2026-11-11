import assert from "node:assert/strict";
import { test } from "node:test";

import { compileFilter, FilterError } from "../js/filter.js";

const rows = [
  { id: 1, src: "192.168.1.23", dst: "140.82.112.3", sport: 50000, dport: 443, proto: "TLS", l4: "tcp", len: 583, info: "Client Hello · github.com" },
  { id: 2, src: "192.168.1.23", dst: "1.1.1.1", sport: 53001, dport: 53, proto: "DNS", l4: "udp", len: 74, info: "Query A github.com" },
  { id: 3, src: "192.168.1.77", dst: "192.168.1.23", sport: 40000, dport: 22, proto: "TCP", l4: "tcp", len: 60, info: "40000 → 22 [SYN]" },
  { id: 4, src: "192.168.1.23", dst: "93.184.215.14", sport: 50100, dport: 80, proto: "HTTP", l4: "tcp", len: 1400, info: "POST shop.example/login" },
  { id: 5, src: "fe80::1", dst: "ff02::1", sport: null, dport: null, proto: "ICMPv6", l4: "icmp6", len: 86, info: "Router Advertisement" },
];

const ids = (expr) => {
  const f = compileFilter(expr);
  return rows.filter((r) => (f ? f(r) : true)).map((r) => r.id);
};

test("empty filter matches everything", () => {
  assert.equal(compileFilter(""), null);
  assert.equal(compileFilter("   "), null);
});

test("ip, src, dst and CIDR", () => {
  assert.deepEqual(ids("ip == 1.1.1.1"), [2]);
  assert.deepEqual(ids("src == 192.168.1.77"), [3]);
  assert.deepEqual(ids("dst == 192.168.1.23"), [3]);
  assert.deepEqual(ids("ip != 192.168.1.23"), [5]);
  assert.deepEqual(ids("dst == 192.168.0.0/16"), [3]);
  assert.deepEqual(ids("ip == 140.82.*"), [1]);
});

test("ports and lengths", () => {
  assert.deepEqual(ids("port == 443"), [1]);
  assert.deepEqual(ids("dport == 53"), [2]);
  assert.deepEqual(ids("len > 1000"), [4]);
  assert.deepEqual(ids("len <= 74"), [2, 3]);
  assert.deepEqual(ids("port != 443"), [2, 3, 4, 5]);
});

test("protocols, aliases and transports", () => {
  assert.deepEqual(ids("protocol == TCP"), [1, 3, 4]);
  assert.deepEqual(ids("proto == tls"), [1]);
  assert.deepEqual(ids("proto == HTTPS"), [1]);
  assert.deepEqual(ids("proto == udp"), [2]);
  assert.deepEqual(ids("proto == icmp"), [5]);
  assert.deepEqual(ids("proto != TCP"), [2, 5]);
});

test("boolean logic, parentheses and implicit and", () => {
  assert.deepEqual(ids("proto == TCP and port == 80"), [4]);
  assert.deepEqual(ids("port == 53 || port == 22"), [2, 3]);
  assert.deepEqual(ids("not proto == TCP"), [2, 5]);
  assert.deepEqual(ids("!(ip == 192.168.1.23)"), [5]);
  assert.deepEqual(ids("(port == 443 or port == 80) and len > 500"), [1, 4]);
  assert.deepEqual(ids("proto == TCP src == 192.168.1.77"), [3]);
});

test("contains and free text", () => {
  assert.deepEqual(ids('info contains "client hello"'), [1]);
  assert.deepEqual(ids("info ~ github"), [1, 2]);
  assert.deepEqual(ids("github"), [1, 2]);
  assert.deepEqual(ids("SYN"), [3]);
});

test("helpful errors", () => {
  assert.throws(() => compileFilter("ip =="), FilterError);
  assert.throws(() => compileFilter("colour == red"), /Unknown field/);
  assert.throws(() => compileFilter("len > big"), /isn't a number/);
  assert.throws(() => compileFilter("(port == 1"), /Missing \)/);
  assert.throws(() => compileFilter('info contains "open'), /Unclosed quote/);
  assert.throws(() => compileFilter("ip == 10.0.0.0/40"), /CIDR/);
});

test("never evaluates code", () => {
  const f = compileFilter("constructor");
  assert.equal(typeof f, "function");
  assert.equal(f(rows[0]), false);
});
