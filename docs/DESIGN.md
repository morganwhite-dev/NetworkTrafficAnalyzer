# Design

The dashboard mixes three looks, and each one has exactly one job:

- **Isometric 3D is for objects.** Devices on the Network map are small isometric models.
- **HUD is for notes on the scene.** Corner brackets frame the thing in focus; notched corners mark a problem.
- **Console style is for anything you read.** Tables, numbers, the incident card and the alerts feed are plain, dense and typographic.

Keeping those jobs separate is what makes it look designed instead of pieced together.

## Tokens

All colours, sizes and timings live as CSS custom properties in `frontend/css/app.css`:

| Token                               | Value                               | Use                                   |
| ----------------------------------- | ----------------------------------- | ------------------------------------- |
| `--bg`                              | `#0a0a0c`                           | page                                  |
| `--panel` / `--panel-2` / `--inset` | `#12151c` / `#171b24` / `#0e1117`   | panels, hover, wells                  |
| `--line` / `--line-soft`            | `#232a36` / `rgba(255,255,255,.06)` | borders                               |
| `--text` / `--text-2` / `--text-3`  | `#d7dde8` / `#8a93a3` / `#4f5868`   | primary, secondary, muted             |
| `--data`                            | `#00ff41`                           | numbers and moving data only          |
| `--hi`                              | `#00f3ff`                           | you, your selection, focus            |
| `--alert` / `--alert-text`          | `#ff003c` / `#ff4d6d`               | problems                              |
| `--warn`                            | `#ffb000`                           | medium severity, cleartext HTTP       |
| `--iso-top/left/right`              | `#283040` / `#1b212c` / `#121720`   | isometric faces (red set for flagged) |

- **Type:** JetBrains Mono 400/500/700 with slashed zeros (`font-feature-settings: "zero"`). Sizes 10, 11, 12, 13, 16 and 20px only. Uppercase labels at 11px with `.08em` tracking.
- **Spacing:** 4px grid. Panel padding 16px, gaps 12px, panel header 36px, top bar 52px, table rows 24px.
- **Panels:** flat `--panel`, 1px `--line-soft` border, a 1px inner highlight on top, 2px radius. No blur, no drop shadows.
- **Panel headers:** a number, a title and one live stat on the right, e.g. `01 / NETWORK ···· 14 HOSTS · 6.1 MB/s · 2 FLAGGED`. "2 FLAGGED" in red is the only key in the UI. There are no legends anywhere.

## Glow budget

Only three things glow (6px blur at most, one shared SVG filter): moving packets on links above 1 MB/s, red or amber items, and the two live top-bar numbers. No glow on text, borders, buttons or icons.

## HUD rules

- Corner brackets mean "focus frame": only on the Network panel and the hover card.
- Notched corners mean "problem": only on red/amber callout tags, the incident card and the "jump to live" pill.
- Never on the table, charts, buttons, inputs or healthy nodes. No hex nodes, scanlines, matrix rain or fake telemetry. Every label is real data.

## Network view: Map tab

- **Floor:** an isometric grid (24-unit cells, `--grid` colour) faded out toward the edges with a radial mask.
- **Home network:** a raised isometric slab (4 units thick) labelled on its front-left face, `HOME NETWORK · 192.168.1.0/24`. This Mac sits at the left of the slab and the router at its right corner, on the boundary. LAN devices fill six slots, busiest first; beyond six, the last slot becomes a faded `+N` cube.
- **Internet:** no slab, just the open floor with a column header `INTERNET · 31 HOSTS`. Top 8 hosts by bandwidth plus a faded outline server labelled `+23 hosts · 1.1 MB/s`. Ranks only change after holding for 3 s; rows slide over 600 ms.
- **Projection:** 2:1 isometric. World x runs down-right, y runs down-left, z runs up: `iso(x, y, z) = [x − y, (x + y)/2 − z]`. Boxes are drawn in ascending x+y+z order with three face shades.
- **Devices** are built from `box()` calls: a laptop (base and lid), a router (body, two antennas, three lights), a phone, a TV (stand and panel), a server stack (three layers with lights) and an unknown cube.
- **Cables:** LAN cables lie on the floor along the grid with one L-shaped turn; internet links are curves through the air. Width is 1–4px on a log scale of bytes/s. Packets are 3px dashes whose gap shrinks and speed rises with throughput; links under 1 KB/s are still and faded.
- **Flagged nodes:** red faces with a red top edge, a breathing red ellipse on the floor, and (for the two most severe) an elbow callout to a notched tag such as `PORT SCAN / 214 ports in 10 s`. Other flagged nodes only get the red treatment.
- **Incident card:** top-left of the map, 296px, notched, with a 2px severity bar:

  ```
  [HIGH]  BANDWIDTH HOG                        1/2  ›
  93.184.215.14 · cdn.example.net · US
  38.2 MB/s     74% of traffic     +410% vs 60 s avg
  since 14:02:11 (42 s) · click to filter
  ```

  With no incidents it collapses to `No active incidents · watching 14 hosts`.

- **Hover:** unrelated items fade to 30%, the path from This Mac turns cyan, and a bracketed hover card shows name, IP, kind, country, MB/s in/out, share, packets, first seen and a 60 s sparkline. **Selected** nodes get a cyan targeting diamond on the floor. Clicking filters the packet table to `ip == X`.

## Network view: Flows tab

Flat (perspective ribbons are hard to read) over the same floor at 50%. A This Mac bar on the left, ribbons sized by share with thin edges, host rows on the right (name, MB/s, share and a 2px share bar) in the same order as the Map. "Others" is hatched. The hog ribbon is red, breathes, carries red dashes and has a notched `+410% vs normal` tag. A 40px total-bandwidth strip along the bottom shades the spike band red.

## Rest of the dashboard

- **Top bar:** brand, a mode chip (`LIVE en0`, `REPLAY demo.pcap` or `FILE capture.pcap`, with a steady red square and elapsed time while capturing), the controls, the interface select, and two glowing readouts (packets/s and bandwidth) that update once a second with no count-up animation.
- **Charts:** Chart.js with no legends and no animation. The bandwidth line is 1.5px green with a gradient fill and red segments during a spike. The donut has `cutout: 80%`, with the protocol names coloured in an HTML table instead of a legend.
- **Geo map:** CARTO `dark_nolabels` tiles, greyscaled, no zoom chrome. Circle markers sized by log of packets, red if flagged, with a one-shot arrival ring. Popups styled like the console and built from DOM nodes.
- **Packet table:** 24px rows, no zebra striping, protocol as coloured text. Selected rows get a cyan tint and bar; flagged rows a red tint and bar. The active filter shows as a chip. "Jump to live" appears when you scroll up.
- **Hex inspector:** 320px, an `8ch 1fr 17ch` grid, `00` bytes dimmed, bytes tinted by layer, `·` for non-printable bytes, linked hex↔ASCII hover. Detected secrets are blurred until clicked.

## Motion

| What                        | How                                                    |
| --------------------------- | ------------------------------------------------------ |
| Packet dashes               | linear, period from gap and speed                      |
| Node and row moves          | `transform`, 600 ms, `cubic-bezier(.2,0,0,1)`          |
| Hover fades                 | opacity, 150 ms                                        |
| Red ellipse and hog ribbon  | 2 s ease-in-out breathing, in sync                     |
| New incident                | callout draws in (240 ms), then the tag wipes in       |
| Scan sweep across the floor | once on capture start and once per new incident, 1.2 s |
| Map arrival ring            | one shot, 1.2 s                                        |

Charts, numbers, panels, idle edges and healthy nodes stay still. Under `prefers-reduced-motion` nothing animates: dashes become static with opacity following throughput, and the red ellipse sits at 0.45.

## Anti-patterns

Glow on text or borders; rounded 12–16px cards, glassmorphism or blur; legends made of coloured dots; icons inside circles; isometric lines at any angle other than 26.57°, horizontal or vertical; several things pulsing at once; rainbow edges or particles on idle links; matrix rain, scanlines or fake telemetry; large blocks of pure green text; default Leaflet and Chart.js chrome; numbers whose decimals jump between updates (always 3 significant figures); rows that reorder every second.
