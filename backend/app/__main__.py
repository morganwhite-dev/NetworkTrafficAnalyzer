"""Entry point: ``python -m app`` (run from the backend/ folder, or via scripts/run.sh)."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .config import LOOPBACK_HOSTS, Settings, default_data_dir

GREEN, CYAN, RED, DIM, RESET = "\033[32m", "\033[36m", "\033[31m", "\033[2m", "\033[0m"


def parse_args(argv: list[str] | None = None) -> Settings:
    s = Settings.from_env()
    p = argparse.ArgumentParser(prog="nta", description="Network Traffic Analyzer")
    p.add_argument("--iface", default=s.iface, help="interface to capture on (default: en0)")
    p.add_argument("--replay", type=Path, default=s.replay,
                   help="replay a .pcap/.pcapng at its original pace (no root needed)")
    p.add_argument("--loop", action="store_true", default=s.loop, help="loop the replay")
    p.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    p.add_argument("--host", default=s.host, help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=s.port)
    p.add_argument("--geo", choices=["auto", "dbip", "ip-api", "off"], default=s.geo,
                   help="Geo-IP source: offline DB-IP (auto/dbip), the online ip-api.com "
                        "service (sends public IPs to a third party), or off")
    p.add_argument("--geo-db", type=Path, default=s.geo_db)
    p.add_argument("--promisc", action="store_true", help="enable promiscuous mode")
    p.add_argument("--allow-remote", action="store_true", default=s.allow_remote,
                   help="allow binding to a non-loopback address (containers only)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)
    s.iface, s.replay, s.loop, s.replay_speed = a.iface, a.replay, a.loop, a.speed
    s.host, s.port, s.geo, s.geo_db = a.host, a.port, a.geo, a.geo_db
    s.promisc, s.allow_remote = a.promisc, a.allow_remote
    return s


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    s = parse_args(argv)
    if not is_loopback(s.host) and not s.allow_remote:
        print(f"{RED}Refusing to listen on {s.host}: the dashboard shows all your traffic. "
              f"Use 127.0.0.1 (pass --allow-remote only inside a container).{RESET}")
        return 2

    # Heavy imports after argument parsing so --help is instant.
    import uvicorn

    from .capture import LiveCapture, open_capture_socket
    from .geoip import GeoResolver
    from .hub import Hub
    from .interfaces import capture_access, default_iface, valid_iface
    from .main import Runtime, create_app
    from .pcapfile import PcapError, normalize_in_child
    from .pipeline import Pipeline
    from .privileges import PrivilegeError, drop_to_sudo_user, running_as_root

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    iface = s.iface or default_iface()
    if s.iface and not valid_iface(s.iface):
        print(f"{RED}Unknown interface {s.iface!r}.{RESET}")
        return 2
    s.iface = iface

    privilege = "user"
    preopened = {}
    if running_as_root() and not s.replay:
        try:
            preopened[iface] = open_capture_socket(iface, s.port, s.promisc)
        except OSError as exc:
            print(f"{RED}Could not open capture on {iface}: {exc}{RESET}")
            return 1
    if running_as_root():
        try:
            user = drop_to_sudo_user()
        except PrivilegeError as exc:
            print(f"{RED}{exc}{RESET}")
            return 1
        if user:
            privilege = "sudo-dropped"
            print(f"{DIM}Opened {iface} as root, then switched to user {user!r}.{RESET}")
        else:
            privilege = "root"
            print(f"{RED}Running as root without sudo (e.g. in a container); "
                  f"privileges were not dropped.{RESET}")
    s.data_dir = default_data_dir() if not os.environ.get("NTA_DATA_DIR") else s.data_dir

    geo = GeoResolver(s.geo, s.geo_db, s.data_dir)
    pipeline = Pipeline(s, geo)
    live = LiveCapture(pipeline, s.port, s.promisc)
    live.preopened.update(preopened)
    live.iface = iface
    rt = Runtime(s, geo, pipeline, live, Hub(pipeline), privilege=privilege)

    if s.replay:
        if not s.replay.exists():
            print(f"{RED}Replay file not found: {s.replay}{RESET}")
            return 2
        norm = rt.workdir / "replay.pcap"
        try:
            info = normalize_in_child(s.replay, norm, s.max_file_packets, s.max_record_bytes,
                                      s.pcap_parse_timeout)
        except PcapError as exc:
            print(f"{RED}{exc}{RESET}")
            return 2
        rt.replay_file, rt.replay_name = norm, s.replay.name
        print(f"{DIM}Replaying {s.replay.name}: {info['packets']} packets"
              f"{' (looping)' if s.loop else ''}.{RESET}")

    app = create_app(rt)
    shown_host = "localhost" if s.host in ("127.0.0.1", "::1", "0.0.0.0") else s.host  # noqa: S104
    url = f"http://{shown_host}:{s.public_port or s.port}/?t={s.token}"
    ok, hint = capture_access()
    print(f"\n  {GREEN}Network Traffic Analyzer {__version__}{RESET}")
    print(f"  Open {CYAN}{url}{RESET}")
    print(f"  {DIM}The link contains a one-time token. Don't share it.{RESET}")
    print(f"  {DIM}Geo-IP: {geo.status['provider']}"
          f"{' (online lookups via ip-api.com)' if geo.provider == 'ip-api' else ''}{RESET}")
    if not s.replay and privilege == "user" and not ok:
        print(f"  {RED}{hint}{RESET}")
    print()

    config = uvicorn.Config(app, host=s.host, port=s.port, log_level="warning",
                            access_log=False, ws_max_size=1 << 20, server_header=False)
    uvicorn.Server(config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
