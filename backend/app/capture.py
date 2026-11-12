"""Packet sources: live BPF capture and paced replay of a capture file."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from .interfaces import addresses, default_route, network_of
from .pcapfile import iter_normalized
from .pipeline import Pipeline


def open_capture_socket(iface: str, port: int, promisc: bool) -> Any:
    """Open a BPF listening socket. Needs root or readable /dev/bpf*."""
    from scapy.all import conf
    kwargs: dict[str, Any] = {"iface": iface, "promisc": promisc}
    if iface.startswith("lo"):
        # Don't capture our own dashboard traffic in a feedback loop.
        kwargs["filter"] = f"not port {int(port)}"
    return conf.L2listen(**kwargs)


class LiveCapture:
    """Wraps Scapy's AsyncSniffer around sockets we open ourselves.

    Sockets opened while the process was still root are kept in
    ``preopened``; after privileges are dropped those are the only
    interfaces that can be captured (unless ChmodBPF makes /dev/bpf* readable).
    """

    def __init__(self, pipeline: Pipeline, port: int, promisc: bool = False) -> None:
        self.pipeline = pipeline
        self.port = port
        self.promisc = promisc
        self.preopened: dict[str, Any] = {}
        self.sniffer = None
        self.iface: str | None = None
        self.error: str | None = None

    def open_socket(self, iface: str) -> Any:
        if iface not in self.preopened:
            self.preopened[iface] = open_capture_socket(iface, self.port, self.promisc)
        return self.preopened[iface]

    def configure_hosts(self, iface: str) -> None:
        v4, v6, mask, _ = addresses(iface)
        route = default_route()
        nets = [n for n in (network_of(a, mask) for a in v4) if n]
        nets += [f"{a}/64" for a in v6 if not a.startswith("fe80")]
        gateway = route.get("gateway") if route.get("interface") == iface else None
        if gateway and not gateway[0].isdigit():
            gateway = None
        with self.pipeline.lock:
            self.pipeline.hosts.configure(set(v4) | set(v6), nets, gateway)
            tunnel = route.get("interface") or ""
            self.pipeline.engine.vpn = {
                "active": tunnel.startswith("utun") and not iface.startswith("utun"),
                "tunnel": tunnel}

    def start(self, iface: str) -> None:
        from scapy.all import AsyncSniffer
        self.stop()
        sock = self.open_socket(iface)
        self.configure_hosts(iface)
        self.iface = iface
        self.error = None
        submit = self.pipeline.submit

        def on_packet(pkt: Any) -> None:
            wirelen = getattr(pkt, "wirelen", None) or len(getattr(pkt, "original", b"") or b"")
            submit(pkt, float(pkt.time), 0, int(wirelen))

        self.sniffer = AsyncSniffer(opened_socket=sock, prn=on_packet, store=False)
        self.sniffer.start()

    def stop(self) -> None:
        if self.sniffer is not None:
            try:
                self.sniffer.stop(join=True)
            except Exception:  # noqa: BLE001
                pass
            self.sniffer = None

    @property
    def running(self) -> bool:
        return bool(self.sniffer and getattr(self.sniffer, "running", False))


class Replayer:
    """Replays a normalised capture at its original pace, re-stamped to 'now'."""

    def __init__(self, pipeline: Pipeline, path: Path, loop: bool, speed: float = 1.0) -> None:
        self.pipeline = pipeline
        self.path = path
        self.loop = loop
        self.speed = max(0.1, speed)
        self.running = threading.Event()
        self.thread: threading.Thread | None = None
        self._quit = False

    def start(self) -> None:
        self.running.set()
        if self.thread is None or not self.thread.is_alive():
            self._quit = False
            self.thread = threading.Thread(target=self._run, name="replay", daemon=True)
            self.thread.start()

    def pause(self) -> None:
        self.running.clear()

    def stop(self) -> None:
        self._quit = True
        self.running.set()

    def _gate(self) -> float | None:
        """Block while paused. Returns the seconds spent paused, or None once stopped."""
        t0 = time.time()
        if not self.running.is_set():
            self.running.wait()
        return None if self._quit else time.time() - t0

    def _run(self) -> None:
        while not self._quit:
            prev_ts = None
            base_wall = time.time()
            base_ts = None
            for ts, raw, wirelen, linktype in iter_normalized(self.path):
                waited = self._gate()
                if waited is None:
                    return
                base_wall += waited
                if base_ts is None:
                    base_ts = ts
                if prev_ts is not None and ts - prev_ts > 1.0:
                    base_ts += (ts - prev_ts) - 1.0      # squash long idle gaps
                prev_ts = ts
                due = base_wall + (ts - base_ts) / self.speed
                delay = due - time.time()
                if delay > 0:
                    time.sleep(min(delay, 1.0))
                    # pause() or stop() may have landed while we slept. Check again, so a packet
                    # from the old source never leaks into whatever the app switched to.
                    waited = self._gate()
                    if waited is None:
                        return
                    base_wall += waited
                self.pipeline.submit(raw, time.time(), linktype, wirelen)
            if not self.loop:
                return
