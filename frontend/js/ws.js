// WebSocket connection with automatic reconnect. Every (re)connect starts
// with a full snapshot from the server, so the UI never drifts.

export function connect(onMessage, onState) {
  let ws = null;
  let delay = 500;
  let pingTimer = null;

  function open() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);
    onState("connecting");
    ws.addEventListener("open", () => {
      delay = 500;
      onState("open");
      clearInterval(pingTimer);
      pingTimer = setInterval(
        () => ws.readyState === 1 && ws.send("ping"),
        20000,
      );
    });
    ws.addEventListener("message", (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      onMessage(msg);
    });
    ws.addEventListener("close", (ev) => {
      clearInterval(pingTimer);
      onState(ev.code === 4403 ? "denied" : "closed");
      if (ev.code === 4403) return;
      setTimeout(open, delay);
      delay = Math.min(delay * 2, 8000);
    });
  }

  open();
  return {
    send(text) {
      if (ws && ws.readyState === 1) ws.send(text);
    },
  };
}
