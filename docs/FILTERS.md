# Filter syntax

Type in the filter bar in the Packet details drawer at the bottom of the window (press `/` to open the drawer and jump to the bar). The table updates as you type. If something doesn't parse, the error shows right next to the box.

## Fields

| Field                    | Matches                         | Example                           |
| ------------------------ | ------------------------------- | --------------------------------- |
| `ip` (or `addr`, `host`) | source or destination           | `ip == 192.168.1.10`              |
| `src`, `dst`             | one side only                   | `src == 192.168.1.77`             |
| `port`                   | source or destination port      | `port == 443`                     |
| `sport`, `dport`         | one side only                   | `dport == 53`                     |
| `proto` (or `protocol`)  | protocol name, or the transport | `proto == TLS`, `protocol == TCP` |
| `len` (or `length`)      | bytes on the wire               | `len > 1000`                      |
| `info`                   | the Info column                 | `info contains "Client Hello"`    |

## Operators

`==`, `!=`, `>`, `<`, `>=`, `<=`, and `contains` (or `~`) for substrings.

Combine terms with `and` / `&&`, `or` / `||`, `not` / `!`, and parentheses. Two terms side by side mean `and`.

## Handy details

- **CIDR ranges and wildcards:** `ip == 10.0.0.0/8`, `ip == 140.82.*`
- **Transports match everything on top of them:** `proto == TCP` includes TLS, HTTP and SSH; `proto == UDP` includes DNS and QUIC; `proto == ICMP` includes ICMPv6; `proto == DNS` includes mDNS.
- **Aliases:** `HTTPS` and `SSL` mean `TLS`, and `HTTP3` means `QUIC`.
- **Anything that isn't a field** is a free-text search across the row: `github`, `SYN`, `NXDOMAIN`.
- **Clicking a node** on the network map, a ribbon on the Flows tab, an alert, or a dot on the World tab sets `ip == <that host>` for you. Click it again, or press `Esc`, to clear it.

## Examples

```text
ip == 192.168.1.77 and proto == TCP          everything the smart TV did over TCP
proto == HTTP and info contains POST         forms sent without encryption
dport == 53 and not dst == 1.1.1.1           DNS going somewhere other than your resolver
proto == QUIC or proto == TLS                encrypted web traffic
len > 1400                                   the big stuff
(port == 22 or port == 23) and src == 10.0.0.0/8
```

The parser is a small hand-written recursive-descent parser in [`frontend/js/filter.js`](../frontend/js/filter.js). It never uses `eval`, and it has its own unit tests.
