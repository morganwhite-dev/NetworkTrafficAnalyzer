// The "How to read this dashboard" dialog, plus the "?" marks on every panel title.
// All wording comes from glossary.js. Text goes in through textContent only.

import { el } from "./format.js";
import { PANEL_TIPS, PROTO_TIPS, SEVERITY_TIPS } from "./glossary.js";

const READING = [
  [
    "Left to right",
    "On the map, your Mac and the devices on your Wi-Fi are on the left. The internet servers you are talking to are on the right.",
  ],
  ["Green dashes", "Data moving. Faster and thicker dashes mean more data."],
  [
    "Red",
    "Something looks wrong with that device or server, and an alert explains it in plain words. Amber means less serious. Everything else is normal.",
  ],
  [
    "Click anything",
    "Click a device, a server, a ribbon, a dot on the World tab, an alert or an address in the packet list, and a card tells you what it is: who owns it, where it is and what it does, in plain English. Its \u201cShow its packets\u201d button opens the Packet details drawer, filtered to that address. Press Esc to close the card.",
  ],
  [
    "Live and Demo",
    "Live watches your real traffic. Demo replays 90 seconds of made-up home traffic that triggers a password leak, a port scan and a bandwidth hog, so you can see what trouble looks like.",
  ],
  [
    "Keys",
    "Press / to open the packet filter. Esc clears it. Arrow keys move through the packet list. The \u22ef menu next to the interface has Clear, Save capture and Open file.",
  ],
];

const PANELS = [
  ["01  Network", "network"],
  ["02  Alerts", "alerts"],
  ["03  Traffic", "traffic"],
  ["04  Packet details", "packets"],
  ["     Inspector", "inspector"],
];

function section(title, ...children) {
  return el(
    "section",
    { class: "help-sec" },
    el("h3", { text: title }),
    ...children,
  );
}

function defs(rows) {
  const dl = el("dl", { class: "help-dl" });
  for (const [k, v, cls] of rows) {
    dl.append(el("dt", { class: cls || "", text: k }), el("dd", { text: v }));
  }
  return dl;
}

export function buildHelpBody() {
  const sev = ["critical", "high", "medium", "low", "info"].map((k) => [
    k.toUpperCase(),
    SEVERITY_TIPS[k].replace(/^\w+: /, ""),
    `key-${k}`,
  ]);
  const protos = Object.entries(PROTO_TIPS).map(([k, v]) => [k, v]);
  return [
    section("The short version", defs(READING)),
    section("Alert severity", defs(sev)),
    section(
      "The panels",
      defs(PANELS.map(([label, key]) => [label, PANEL_TIPS[key]])),
    ),
    section("Protocols, in plain English", defs(protos)),
  ];
}

/** Fill the "?" marks next to panel titles from the glossary. */
export function fillPanelTips(root = document) {
  for (const node of root.querySelectorAll("[data-help]")) {
    const tip = PANEL_TIPS[node.dataset.help];
    if (tip) node.setAttribute("data-tip", tip);
  }
}

export function initHelp({ dialog, body, openers, closer }) {
  body.replaceChildren(...buildHelpBody());
  const open = () => {
    if (!dialog.open) dialog.showModal();
  };
  for (const b of openers) b.addEventListener("click", open);
  closer.addEventListener("click", () => dialog.close());
  // Click on the backdrop closes it.
  dialog.addEventListener("click", (ev) => {
    if (ev.target === dialog) dialog.close();
  });
  return { open };
}
