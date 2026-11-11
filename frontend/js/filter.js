// Packet filter language. Pure module: no DOM, no eval/new Function.
//
//   ip == 192.168.1.10        src / dst / ip (either side), CIDR ok: ip == 10.0.0.0/8
//   port == 443               sport / dport / port (either side)
//   proto == TLS              protocol name, or TCP/UDP/ICMP for the transport
//   len > 1000                == != > < >= <=
//   info contains "Hello"     substring, case-insensitive
//   not, and, or, &&, ||, !, ( )
//   anything else             free-text search across the row
//
// See docs/FILTERS.md for the full reference.

export class FilterError extends Error {
  constructor(message, pos) {
    super(message);
    this.pos = pos;
  }
}

const FIELDS = {
  ip: "ip",
  src: "src",
  dst: "dst",
  addr: "ip",
  host: "ip",
  port: "port",
  sport: "sport",
  dport: "dport",
  srcport: "sport",
  dstport: "dport",
  proto: "proto",
  protocol: "proto",
  len: "len",
  length: "len",
  size: "len",
  info: "info",
};
const OPS = ["==", "!=", ">=", "<=", ">", "<", "contains", "~", "="];
const PROTO_ALIASES = { HTTPS: "TLS", SSL: "TLS", HTTP3: "QUIC", MDNS: "mDNS" };

function tokenize(input) {
  const tokens = [];
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(" || c === ")") {
      tokens.push({ t: c, pos: i });
      i++;
      continue;
    }
    const two = input.slice(i, i + 2);
    if (["==", "!=", ">=", "<=", "&&", "||"].includes(two)) {
      tokens.push({ t: "op", v: two, pos: i });
      i += 2;
      continue;
    }
    if (c === ">" || c === "<" || c === "~" || c === "=") {
      tokens.push({ t: "op", v: c, pos: i });
      i++;
      continue;
    }
    if (c === "!") {
      tokens.push({ t: "op", v: "!", pos: i });
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const end = input.indexOf(c, i + 1);
      if (end === -1) throw new FilterError("Unclosed quote", i);
      tokens.push({ t: "str", v: input.slice(i + 1, end), pos: i });
      i = end + 1;
      continue;
    }
    let j = i;
    while (
      j < input.length &&
      !/[\s()]/.test(input[j]) &&
      !["==", "!=", ">=", "<=", "&&", "||"].includes(input.slice(j, j + 2)) &&
      !(j > i && /[><~=!]/.test(input[j]))
    )
      j++;
    if (j === i) j = i + 1;
    tokens.push({ t: "word", v: input.slice(i, j), pos: i });
    i = j;
  }
  return tokens;
}

function ipv4ToInt(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return (
    ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
  );
}

function ipMatcher(value, pos) {
  const v = value.toLowerCase();
  if (v.includes("/")) {
    const [base, bitsS] = v.split("/");
    const bits = Number(bitsS);
    const baseInt = ipv4ToInt(base);
    if (baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
      throw new FilterError(`"${value}" isn't a valid IPv4 CIDR range`, pos);
    }
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (addr) => {
      const n = ipv4ToInt(addr || "");
      return n !== null && (n & mask) >>> 0 === (baseInt & mask) >>> 0;
    };
  }
  if (v.endsWith("*")) {
    const prefix = v.slice(0, -1);
    return (addr) => (addr || "").toLowerCase().startsWith(prefix);
  }
  return (addr) => (addr || "").toLowerCase() === v;
}

function protoMatches(row, want) {
  const w = PROTO_ALIASES[want.toUpperCase()] || want;
  const p = (row.proto || "").toLowerCase();
  const wl = w.toLowerCase();
  if (p === wl) return true;
  if (wl === "tcp" || wl === "udp") return (row.l4 || "") === wl;
  if (wl === "icmp") return p === "icmp" || p === "icmpv6";
  if (wl === "dns") return p === "dns" || p === "mdns";
  return false;
}

function compare(op, a, b) {
  switch (op) {
    case "==":
    case "=":
      return a === b;
    case "!=":
      return a !== b;
    case ">":
      return a > b;
    case "<":
      return a < b;
    case ">=":
      return a >= b;
    case "<=":
      return a <= b;
    default:
      return false;
  }
}

function comparison(field, op, rawValue, pos) {
  const value = String(rawValue);
  const contains = op === "contains" || op === "~";
  if (field === "ip" || field === "src" || field === "dst") {
    if (!["==", "=", "!=", "contains", "~"].includes(op)) {
      throw new FilterError(`Use == or != with ${field}`, pos);
    }
    const m = contains
      ? (a) => (a || "").includes(value)
      : ipMatcher(value, pos);
    let test;
    if (field === "ip") test = (r) => m(r.src) || m(r.dst);
    else test = (r) => m(r[field]);
    return op === "!=" ? (r) => !test(r) : test;
  }
  if (
    field === "port" ||
    field === "sport" ||
    field === "dport" ||
    field === "len"
  ) {
    const n = Number(value);
    if (!Number.isFinite(n))
      throw new FilterError(`"${value}" isn't a number`, pos);
    if (contains)
      throw new FilterError(`Use a comparison like == or > with ${field}`, pos);
    if (field === "port") {
      return op === "!="
        ? (r) => r.sport !== n && r.dport !== n
        : (r) => compare(op, r.sport, n) || compare(op, r.dport, n);
    }
    return (r) =>
      r[field] !== null && r[field] !== undefined && compare(op, r[field], n);
  }
  if (field === "proto") {
    if (contains)
      return (r) => (r.proto || "").toLowerCase().includes(value.toLowerCase());
    if (op !== "==" && op !== "=" && op !== "!=") {
      throw new FilterError("Use == or != with proto", pos);
    }
    return op === "!="
      ? (r) => !protoMatches(r, value)
      : (r) => protoMatches(r, value);
  }
  if (field === "info") {
    const v = value.toLowerCase();
    if (contains) return (r) => (r.info || "").toLowerCase().includes(v);
    if (op === "!=") return (r) => (r.info || "").toLowerCase() !== v;
    return (r) => (r.info || "").toLowerCase() === v;
  }
  throw new FilterError(`Unknown field "${field}"`, pos);
}

function freeText(word) {
  const v = word.toLowerCase();
  return (r) =>
    [
      r.src,
      r.dst,
      r.proto,
      r.info,
      String(r.sport ?? ""),
      String(r.dport ?? ""),
    ].some((x) => (x || "").toLowerCase().includes(v));
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.i = 0;
  }
  peek() {
    return this.tokens[this.i];
  }
  next() {
    return this.tokens[this.i++];
  }
  isWord(tok, ...words) {
    return tok && tok.t === "word" && words.includes(tok.v.toLowerCase());
  }

  parseOr() {
    let left = this.parseAnd();
    for (;;) {
      const t = this.peek();
      if (this.isWord(t, "or") || (t && t.t === "op" && t.v === "||")) {
        this.next();
        const right = this.parseAnd();
        const l = left;
        left = (r) => l(r) || right(r);
      } else return left;
    }
  }

  parseAnd() {
    let left = this.parseNot();
    for (;;) {
      const t = this.peek();
      if (this.isWord(t, "and") || (t && t.t === "op" && t.v === "&&")) {
        this.next();
        const right = this.parseNot();
        const l = left;
        left = (r) => l(r) && right(r);
      } else if (
        t &&
        t.t !== ")" &&
        !this.isWord(t, "or") &&
        !(t.t === "op" && t.v === "||")
      ) {
        const right = this.parseNot(); // implicit AND between terms
        const l = left;
        left = (r) => l(r) && right(r);
      } else return left;
    }
  }

  parseNot() {
    const t = this.peek();
    if (this.isWord(t, "not") || (t && t.t === "op" && t.v === "!")) {
      this.next();
      const inner = this.parseNot();
      return (r) => !inner(r);
    }
    return this.parsePrimary();
  }

  parsePrimary() {
    const t = this.next();
    if (!t)
      throw new FilterError(
        "Filter ends too early",
        this.tokens.length ? this.tokens.at(-1).pos : 0,
      );
    if (t.t === "(") {
      const inner = this.parseOr();
      const close = this.next();
      if (!close || close.t !== ")") throw new FilterError("Missing )", t.pos);
      return inner;
    }
    if (t.t === ")") throw new FilterError("Unexpected )", t.pos);
    if (t.t === "op") throw new FilterError(`Unexpected "${t.v}"`, t.pos);
    const fieldName = t.t === "word" ? FIELDS[t.v.toLowerCase()] : undefined;
    const opTok = this.peek();
    const isOp =
      opTok &&
      ((opTok.t === "op" && OPS.includes(opTok.v)) ||
        this.isWord(opTok, "contains"));
    if (fieldName && isOp) {
      this.next();
      const op = opTok.t === "op" ? opTok.v : "contains";
      const val = this.next();
      if (!val || (val.t !== "word" && val.t !== "str")) {
        throw new FilterError(`Missing value after "${op}"`, opTok.pos);
      }
      return comparison(fieldName, op, val.v, val.pos);
    }
    if (t.t === "word" && isOp && !fieldName) {
      throw new FilterError(`Unknown field "${t.v}"`, t.pos);
    }
    return freeText(t.v);
  }
}

/** Compile a filter string. Returns null for an empty filter. Throws FilterError. */
export function compileFilter(input) {
  const text = (input || "").trim();
  if (!text) return null;
  const tokens = tokenize(text);
  const p = new Parser(tokens);
  const pred = p.parseOr();
  if (p.i < tokens.length)
    throw new FilterError(
      `Unexpected "${tokens[p.i].v || tokens[p.i].t}"`,
      tokens[p.i].pos,
    );
  return pred;
}
