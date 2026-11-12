"""Packet sources: live BPF capture and paced replay of a capture file."""

from __future__ import annotations

import os
import select
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

from scapy.all import conf

from .interfaces import addresses, default_route, network_of
from .pcapfile import iter_normalized
from .pipeline import Pipeline

# The kernel keeps packets in this buffer until we read them. Scapy asks for 64 KB, which fills in
# a few tens of milliseconds on a busy connection; if we are not reading by then the kernel
# silently throws packets away. 512 KB is macOS's maximum (sysctl debug.bpf_maxbufsize).
BPF_BUFFER = 512 * 1024
_BPF_HEADER = struct.Struct("=IIIIH")      # tv_sec, tv_usec, caplen, datalen, hdrlen (macOS)


def open_capture_socket(iface: str, port: int, promisc: bool) -> Any:
    """Open a BPF listening socket. Needs root or readable /dev/bpf*."""
    kwargs: dict[str, Any] = {"iface": iface, "promisc": promisc}
    if iface.startswith("lo"):
        # Don't capture our own dashboard traffic in a feedback loop.
        kwargs["filter"] = f"not port {int(port)}"
    if sys.platform != "darwin":
        return conf.L2listen(**kwargs)
    from scapy.arch.bpf import supersocket as bpf
    asked = bpf.BPF_BUFFER_LENGTH
    bpf.BPF_BUFFER_LENGTH = BPF_BUFFER          # read by Scapy while it configures the socket
    try:
        return conf.L2listen(**kwargs)
    finally:
        bpf.BPF_BUFFER_LENGTH = asked


class BpfReader(threading.Thread):
    """Reads a BPF socket as fast as it can and hands raw frames to the pipeline.

    Scapy's own reader does much more per packet (it builds a packet object, re-slices the
    buffer for every frame and pops from the front of a list), and that is enough to fall
    behind on a fast download. Here a read is one syscall, a frame is one `struct` unpack,
    and nothing is parsed: parsing happens on the pipeline thread. The kernel's own
    received/dropped counters are copied to the pipeline, so loss is never silent.
    """

    def __init__(self, sock: Any, pipeline: Pipeline) -> None:
        super().__init__(name="bpf-reader", daemon=True)
        self.sock = sock
        self.pipeline = pipeline
        self.linktype = int(conf.l2types.layer2num.get(sock.guessed_cls, 1))
        self.blen = sock.get_blen() or BPF_BUFFER
        self.halt = threading.Event()
        self.base_recv, self.base_drop = self._kernel() or (0, 0)

    def _kernel(self) -> tuple[int, int] | None:
        try:
            recv, drop = self.sock.get_stats()
        except Exception:  # noqa: BLE001 - the socket may be closing
            return None
        return None if recv is None else (int(recv), int(drop))

    def _publish(self) -> None:
        k = self._kernel()
        if k:
            self.pipeline.set_kernel_stats(k[0] - self.base_recv, k[1] - self.base_drop)

    def stop(self) -> None:
        self.halt.set()
        self.join(timeout=2)
        self._publish()

    def run(self) -> None:
        fd = self.sock.bpf_fd
        submit = self.pipeline.submit
        unpack = _BPF_HEADER.unpack_from
        hdr = _BPF_HEADER.size
        # Let this thread run promptly even while the pipeline thread is busy analysing.
        sys.setswitchinterval(0.001)
        last = 0.0
        while not self.halt.is_set():
            ready, _, _ = select.select([fd], [], [], 0.25)
            now = time.monotonic()
            if now - last >= 0.5:
                self._publish()
                last = now
            if not ready:
                continue
            try:
                data = os.read(fd, self.blen)
            except OSError:
                if self.halt.is_set():
                    return
                time.sleep(0.05)
                continue
            n = len(data)
            off = 0
            while off + hdr <= n:
                sec, usec, caplen, datalen, hdrlen = unpack(data, off)
                start = off + hdrlen
                if hdrlen < hdr or start + caplen > n:
                    break                              # a damaged buffer: drop the tail
                if caplen:
                    submit(data[start:start + caplen], sec + usec * 1e-6, self.linktype, datalen)
                off += (hdrlen + caplen + 3) & ~3       # BPF_WORDALIGN, 4 bytes on macOS


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
        self.reader: BpfReader | None = None
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
        if hasattr(sock, "bpf_fd"):
            self.reader = BpfReader(sock, self.pipeline)
            self.reader.start()
            return
        submit = self.pipeline.submit        # Linux: Scapy's own reader

        def on_packet(pkt: Any) -> None:
            wirelen = getattr(pkt, "wirelen", None) or len(getattr(pkt, "original", b"") or b"")
            submit(pkt, float(pkt.time), 0, int(wirelen))

        self.sniffer = AsyncSniffer(opened_socket=sock, prn=on_packet, store=False)
        self.sniffer.start()

    def stop(self) -> None:
        if self.reader is not None:
            self.reader.stop()
            self.reader = None
        if self.sniffer is not None:
            try:
                self.sniffer.stop(join=True)
            except Exception:  # noqa: BLE001
                pass
            self.sniffer = None

    @property
    def running(self) -> bool:
        if self.reader is not None:
            return self.reader.is_alive()
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
