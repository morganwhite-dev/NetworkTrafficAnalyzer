"""WebSocket fan-out with a bounded send queue per client.

A slow browser tab can't make the server buffer without limit: if its queue
fills up, that client is disconnected (it reconnects and gets a fresh
snapshot).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from .pipeline import Pipeline

TICK = 0.2
MAX_ROWS_PER_MESSAGE = 2000
CLIENT_QUEUE = 300


class Client:
    def __init__(self, ws: WebSocket) -> None:
        self.ws = ws
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=CLIENT_QUEUE)
        self.closed = False


class Hub:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self.clients: set[Client] = set()
        self.status_provider = None  # callable returning the /api/status dict
        self.wifi = None             # WifiMonitor, when enabled

    def broadcast(self, message: dict[str, Any]) -> None:
        if not self.clients:
            return
        text = json.dumps(message, separators=(",", ":"), default=str)
        for c in list(self.clients):
            if c.closed:
                continue
            try:
                c.queue.put_nowait(text)
            except asyncio.QueueFull:
                c.closed = True
                asyncio.get_running_loop().create_task(self._drop(c))

    async def _drop(self, c: Client) -> None:
        self.clients.discard(c)
        with contextlib.suppress(Exception):
            await c.ws.close(code=4008, reason="Client too slow; reconnect for a snapshot.")

    async def send_snapshot_all(self) -> None:
        snap = await asyncio.to_thread(self.pipeline.snapshot)
        if self.status_provider:
            snap["status"] = self.status_provider()
        self.broadcast(snap)

    def wifi_message(self) -> dict[str, Any]:
        bps = None
        if self.pipeline.mode in ("live", "replay"):
            bps = self.pipeline.stats_message().get("bps")
        return self.wifi.message(bps)  # type: ignore[union-attr]

    async def serve(self, ws: WebSocket) -> None:
        await ws.accept()
        client = Client(ws)
        snap = await asyncio.to_thread(self.pipeline.snapshot)
        if self.status_provider:
            snap["status"] = self.status_provider()
        if self.wifi is not None:
            snap["wifi"] = await asyncio.to_thread(self.wifi_message)
        await ws.send_text(json.dumps(snap, separators=(",", ":"), default=str))
        self.clients.add(client)
        sender = asyncio.create_task(self._sender(client))
        try:
            while True:
                msg = await ws.receive_text()
                if msg == "ping":
                    with contextlib.suppress(asyncio.QueueFull):
                        client.queue.put_nowait('{"type":"pong"}')
                elif msg == "wifi:on" and self.wifi is not None:
                    self.wifi.keepalive()
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            client.closed = True
            self.clients.discard(client)
            sender.cancel()

    async def _sender(self, c: Client) -> None:
        try:
            while not c.closed:
                text = await c.queue.get()
                await c.ws.send_text(text)
        except Exception:  # noqa: BLE001
            c.closed = True
            self.clients.discard(c)

    async def run(self) -> None:
        n = 0
        while True:
            await asyncio.sleep(TICK)
            n += 1
            rows, skipped, alerts = self.pipeline.take_outbox()
            if rows:
                extra = max(0, len(rows) - MAX_ROWS_PER_MESSAGE)
                self.broadcast({"type": "packets", "items": rows[-MAX_ROWS_PER_MESSAGE:],
                                "skipped": skipped + extra,
                                "generation": self.pipeline.generation})
            for a in alerts:
                kind = "alert_update" if a.pop("update", False) else "alert"
                self.broadcast({"type": kind, "alert": a})
            if n % 5 == 0:
                await asyncio.to_thread(self.pipeline.tick)
                if self.clients:
                    self.broadcast(await asyncio.to_thread(self.pipeline.stats_message))
                    self.broadcast(await asyncio.to_thread(self.pipeline.netview_message))
            if n % 10 == 0 and self.clients:
                self.broadcast(await asyncio.to_thread(self.pipeline.geo_message))
            if n % 10 == 5 and self.clients and self.wifi is not None:
                self.broadcast(await asyncio.to_thread(self.wifi_message))
