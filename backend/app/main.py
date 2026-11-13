"""FastAPI application: REST routes, the WebSocket and the static dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import shutil
import tempfile
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, ipinfo
from .apps import AppMap
from .capture import LiveCapture, Replayer
from .config import FRONTEND_DIR, Settings
from .geoip import GeoResolver
from .hub import Hub
from .interfaces import capture_access, list_interfaces, valid_iface
from .pcapfile import PcapError, check_magic, iter_normalized, normalize_in_child
from .pipeline import Pipeline
from .security import SecurityMiddleware
from .textsafe import clean
from .wifi import WifiMonitor

ALLOWED_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]"]


@dataclass
class Runtime:
    settings: Settings
    geo: GeoResolver
    pipeline: Pipeline
    live: LiveCapture
    hub: Hub
    privilege: str = "user"            # user | sudo-dropped | root
    replay_file: Path | None = None    # normalised copy of --replay
    replay_name: str = ""
    replay_auto: bool = True           # start the replay at launch (False: only on demand)
    replay_loop: bool | None = None    # None: follow --loop
    replayer: Replayer | None = None
    wifi: WifiMonitor | None = None
    apps: AppMap | None = None
    launch_url: str | None = None
    upload_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    mode_lock: asyncio.Lock = field(default_factory=asyncio.Lock)   # serialises source switches
    workdir: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="nta-")))

    @property
    def capturing(self) -> bool:
        if self.pipeline.mode == "live":
            return self.live.running
        if self.pipeline.mode == "replay" and self.replayer:
            return self.replayer.running.is_set()
        return False

    def status(self) -> dict[str, Any]:
        ok, hint = capture_access()
        preopened = sorted(self.live.preopened)
        if self.privilege == "sudo-dropped":
            ok, hint = bool(preopened), ("Root was dropped after opening "
                                         f"{', '.join(preopened)}. Restart with sudo to "
                                         "capture on another interface.")
        return {
            "type": "status",
            "version": __version__,
            "mode": self.pipeline.mode,
            "source": self.pipeline.source,
            "capturing": self.capturing,
            "iface": self.live.iface,
            "replay": self.replay_name or None,
            "capture": {"ok": ok, "hint": hint, "privilege": self.privilege,
                        "interfaces": preopened if self.privilege == "sudo-dropped" else None,
                        "error": self.live.error},
            "geo": self.geo.status,
            "limits": {"upload_mb": self.settings.max_upload_bytes // (1024 * 1024)},
        }


def create_app(rt: Runtime) -> FastAPI:
    s = rt.settings
    rt.hub.status_provider = rt.status
    rt.hub.wifi = rt.wifi
    rt.hub.capturing = lambda: rt.capturing

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        tasks = [asyncio.create_task(rt.hub.run()), asyncio.create_task(rt.geo.run())]
        if rt.wifi:
            rt.wifi.start()
        if rt.apps:
            rt.apps.start()
        if rt.replay_file and rt.replay_auto:
            start_replay(rt)
        elif rt.settings.autostart:
            await autostart_capture(rt)
        if rt.settings.open_browser and rt.launch_url:
            asyncio.get_running_loop().call_later(
                0.6, lambda: webbrowser.open(rt.launch_url))  # type: ignore[arg-type]
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            rt.live.stop()
            if rt.replayer:
                rt.replayer.stop()
            rt.pipeline.close()
            if rt.wifi:
                rt.wifi.stop()
            if rt.apps:
                rt.apps.stop()
            shutil.rmtree(rt.workdir, ignore_errors=True)

    app = FastAPI(title="Network Traffic Analyzer", version=__version__, docs_url=None,
                  redoc_url=None, openapi_url=None, lifespan=lifespan)

    # ------------------------------------------------------------ pages
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html", media_type="text/html")

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "favicon.svg", media_type="image/svg+xml")

    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    # ------------------------------------------------------------- api
    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return rt.status()

    @app.get("/api/interfaces")
    async def interfaces() -> dict[str, Any]:
        items = await asyncio.to_thread(list_interfaces)
        return {"items": [i.to_dict() for i in items], "default": rt.live.iface or s.iface}

    @app.post("/api/capture/start")
    async def capture_start(request: Request) -> dict[str, Any]:
        body = await _json(request)
        iface = body.get("iface")
        # One mode change at a time: a double click or a second tab must not interleave
        # two switches and leave demo data labelled as live.
        async with rt.mode_lock:
            if iface == "replay" and rt.replay_file:   # only this literal selects the demo
                if rt.pipeline.mode != "replay":
                    await asyncio.to_thread(rt.live.stop)
                    rt.pipeline.clear()
                    start_replay(rt)
                    await rt.hub.send_snapshot_all()
                elif rt.replayer:
                    rt.replayer.start()
                rt.hub.broadcast(rt.status())
                return rt.status()
            iface = iface or rt.live.iface or s.iface
            if not isinstance(iface, str) or not valid_iface(iface):
                raise HTTPException(400, "Unknown network interface.")
            if rt.privilege == "sudo-dropped" and iface not in rt.live.preopened:
                raise HTTPException(409, f"Root was dropped at startup. Restart with sudo and "
                                         f"--iface {iface} to capture there.")
            was_demo = rt.pipeline.mode == "replay" and rt.capturing
            if rt.replayer:
                rt.replayer.pause()
            changed = rt.pipeline.mode != "live" or rt.pipeline.source != iface
            if changed:
                await asyncio.to_thread(rt.live.stop)
                rt.pipeline.clear()
            try:
                await asyncio.to_thread(rt.live.start, iface)
            except Exception as exc:  # noqa: BLE001 - Scapy raises its own exception types
                text = str(exc)
                if isinstance(exc, PermissionError) or "Permission denied" in text \
                        or "Operation not permitted" in text:
                    rt.live.error = "Permission denied opening the capture device."
                    detail, code = capture_access()[1], 403
                else:
                    rt.live.error = clean(text, 200)
                    detail, code = f"Could not start capture: {rt.live.error}", 409
                if was_demo and rt.replay_file:
                    # Live could not start: put the demo back the way it was, instead of
                    # leaving an empty, paused "replay".
                    start_replay(rt)
                    await rt.hub.send_snapshot_all()
                rt.hub.broadcast(rt.status())
                raise HTTPException(code, detail) from exc
            rt.pipeline.mode, rt.pipeline.source = "live", iface
            if changed:
                await rt.hub.send_snapshot_all()
            rt.hub.broadcast(rt.status())
            return rt.status()

    @app.post("/api/capture/stop")
    async def capture_stop() -> dict[str, Any]:
        async with rt.mode_lock:
            await asyncio.to_thread(rt.live.stop)
            if rt.replayer:
                rt.replayer.pause()
            rt.hub.broadcast(rt.status())
            return rt.status()

    @app.post("/api/clear")
    async def clear() -> dict[str, Any]:
        async with rt.mode_lock:
            rt.pipeline.clear()
            await rt.hub.send_snapshot_all()
        return {"ok": True}

    @app.get("/api/ip/{ip}")
    async def ip_info(ip: str) -> dict[str, Any]:
        """Click an address, learn what it is. Looks up only the one address you asked about."""
        try:
            addr = str(ipaddress.ip_address(ip.split("%")[0]))
        except ValueError as exc:
            raise HTTPException(400, "That is not an IP address.") from exc
        local = await asyncio.to_thread(rt.pipeline.host_info, addr)
        return await asyncio.to_thread(ipinfo.lookup, addr, local, s.ip_lookup)

    @app.get("/api/packets/{pid}")
    async def packet(pid: int) -> dict[str, Any]:
        data = await asyncio.to_thread(rt.pipeline.inspect, pid)
        if data is None:
            raise HTTPException(404, "That packet is no longer in the buffer.")
        return data

    @app.post("/api/alerts/{aid}/reveal")
    async def reveal(aid: int) -> dict[str, Any]:
        secret = rt.pipeline.reveal(aid)
        if secret is None:
            raise HTTPException(404, "Nothing to reveal for that alert.")
        return {"secret": secret}

    @app.get("/api/export.pcap")
    async def export(headers_only: int = 0) -> Response:
        def build() -> bytes:
            with rt.pipeline.lock:
                return rt.pipeline.store.export_pcap(bool(headers_only))
        data = await asyncio.to_thread(build)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        suffix = "-headers" if headers_only else ""
        # Say where the data came from, so an exported demo can't pass for a real capture.
        origin = {"replay": "demo-", "file": "file-"}.get(rt.pipeline.mode, "")
        return Response(data, media_type="application/vnd.tcpdump.pcap", headers={
            "content-disposition": f'attachment; filename="nta-{origin}{stamp}{suffix}.pcap"'})

    @app.post("/api/pcap")
    async def upload(request: Request) -> dict[str, Any]:
        if rt.upload_lock.locked():
            raise HTTPException(429, "Another file is being analysed. Try again in a moment.")
        async with rt.upload_lock:
            declared = request.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > s.max_upload_bytes:
                raise HTTPException(413, f"File is larger than {s.max_upload_bytes // 2**20} MB.")
            name = clean(unquote(request.headers.get("x-nta-filename", "upload.pcap")), 80)
            src = rt.workdir / "upload.bin"
            dst = rt.workdir / "upload.norm.pcap"
            total, head = 0, b""
            with open(src, "wb") as fh:
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > s.max_upload_bytes:
                        fh.close()
                        src.unlink(missing_ok=True)
                        raise HTTPException(413, "File is too large.")
                    if len(head) < 4:
                        head += chunk[:4]
                        try:
                            if len(head) >= 4:
                                check_magic(head)
                        except PcapError as exc:
                            fh.close()
                            src.unlink(missing_ok=True)
                            raise HTTPException(415, str(exc)) from exc
                    fh.write(chunk)
            try:
                info = await asyncio.to_thread(normalize_in_child, src, dst, s.max_file_packets,
                                               s.max_record_bytes, s.pcap_parse_timeout)
            except PcapError as exc:
                raise HTTPException(422, str(exc)) from exc
            finally:
                src.unlink(missing_ok=True)
            async with rt.mode_lock:
                await asyncio.to_thread(rt.live.stop)
                if rt.replayer:
                    rt.replayer.pause()
                await asyncio.to_thread(load_file, rt, dst, name)
                dst.unlink(missing_ok=True)
                await rt.hub.send_snapshot_all()
                rt.hub.broadcast(rt.status())
            return {"ok": True, "name": name, **info}

    @app.post("/api/geo/clear")
    async def geo_clear() -> dict[str, Any]:
        await asyncio.to_thread(rt.geo.clear_cache)
        return {"ok": True}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        await rt.hub.serve(websocket)

    secured = SecurityMiddleware(app, s.token, s.public_origins, s.public_port or s.port)
    # Host checks stay strict even in a container: browsers reach it as localhost.
    outer = TrustedHostMiddleware(secured, allowed_hosts=ALLOWED_HOSTS)
    return outer  # type: ignore[return-value]


async def _json(request: Request) -> dict[str, Any]:
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        return {}
    with contextlib.suppress(Exception):
        data = await request.json()
        if isinstance(data, dict):
            return data
    return {}


async def autostart_capture(rt: Runtime) -> None:
    """Start live capture at launch (used by the Mac app). Never fatal."""
    iface = rt.live.iface or rt.settings.iface
    if not iface:
        return
    ok, _ = capture_access()
    if not ok and iface not in rt.live.preopened:
        return
    try:
        await asyncio.to_thread(rt.live.start, iface)
    except Exception as exc:  # noqa: BLE001 - the dashboard shows the error instead
        rt.live.error = clean(str(exc), 200)
        return
    rt.pipeline.mode, rt.pipeline.source = "live", iface


def start_replay(rt: Runtime) -> None:
    if not rt.replay_file:
        return
    if rt.replayer:
        rt.replayer.stop()
    rt.pipeline.mode, rt.pipeline.source = "replay", rt.replay_name
    with rt.pipeline.lock:
        rt.pipeline.hosts.configure(set(), [], None)
        rt.pipeline.engine.vpn = {"active": False}
    loop = rt.settings.loop if rt.replay_loop is None else rt.replay_loop
    rt.replayer = Replayer(rt.pipeline, rt.replay_file, loop, rt.settings.replay_speed)
    rt.replayer.start()


def load_file(rt: Runtime, path: Path, name: str) -> None:
    """Analyse a normalised capture file as fast as possible (file mode)."""
    p = rt.pipeline
    p.clear()
    with p.lock:
        p.mode, p.source = "file", name
        p.hosts.configure(set(), [], None)
        p.engine.vpn = {"active": False}
    last = 0.0
    for ts, raw, wirelen, linktype in iter_normalized(path):
        p.process_now(raw, ts, linktype, wirelen)
        last = ts
    with p.lock:
        p.engine.advance(last + 2)
        p.out_rows.clear()
        p.alerts.fresh.clear()
        p.alerts.updated.clear()
