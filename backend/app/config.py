"""Runtime settings, filled from CLI flags and NTA_* environment variables."""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = REPO_ROOT / "frontend"
MIN_TOKEN_LEN = 16
DEMO_PCAP = REPO_ROOT / "samples" / "demo.pcap"   # bundled demo, offered by the Live/Demo toggle
DEFAULT_GEO_DB = REPO_ROOT / "data" / "dbip-city-lite.mmdb"

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def default_data_dir() -> Path:
    """Per-user folder for the Geo-IP cache (never inside the repo)."""
    override = os.environ.get("NTA_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "NetworkTrafficAnalyzer"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "network-traffic-analyzer"


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8000
    iface: str | None = None
    replay: Path | None = None
    loop: bool = False
    replay_speed: float = 1.0
    geo: str = "auto"  # auto | dbip | ip-api | off
    geo_db: Path = DEFAULT_GEO_DB
    data_dir: Path = field(default_factory=default_data_dir)
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    allow_remote: bool = False
    public_port: int | None = None   # host port when Docker maps a different one
    promisc: bool = False
    ip_lookup: bool = True            # ask ipwho.is who owns an address you click on
    wifi_target: str = "1.1.1.1"
    open_browser: bool = False      # open the dashboard when the server is ready
    autostart: bool = False         # start live capture on launch (the Mac app does this)

    # Hard limits (see docs/ARCHITECTURE.md, "Limits").
    max_upload_bytes: int = 200 * 1024 * 1024
    ring_bytes: int = 128 * 1024 * 1024
    queue_max: int = 50_000
    max_hosts: int = 10_000
    max_alerts: int = 500
    max_file_packets: int = 2_000_000
    max_record_bytes: int = 256 * 1024
    pcap_parse_timeout: float = 120.0

    @property
    def public_origins(self) -> set[str]:
        port = self.public_port or self.port
        return {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}

    @classmethod
    def from_env(cls) -> Settings:
        s = cls()
        env = os.environ
        s.host = env.get("NTA_HOST", s.host)
        s.port = int(env.get("NTA_PORT", s.port))
        s.iface = env.get("NTA_IFACE") or None
        if env.get("NTA_REPLAY"):
            s.replay = Path(env["NTA_REPLAY"])
        s.loop = env.get("NTA_LOOP", "0") == "1"
        s.geo = env.get("NTA_GEO", s.geo)
        if env.get("NTA_GEO_DB"):
            s.geo_db = Path(env["NTA_GEO_DB"])
        if env.get("NTA_TOKEN"):
            if len(env["NTA_TOKEN"]) < MIN_TOKEN_LEN:
                raise ValueError(
                    f"NTA_TOKEN must be at least {MIN_TOKEN_LEN} characters (it is the only "
                    "thing between other local programs and your traffic). Leave it unset to "
                    "get a random one."
                )
            s.token = env["NTA_TOKEN"]
        s.allow_remote = env.get("NTA_ALLOW_REMOTE", "0") == "1"
        s.ip_lookup = env.get("NTA_IP_LOOKUP", "1") != "0"
        if env.get("NTA_PUBLIC_PORT"):
            s.public_port = int(env["NTA_PUBLIC_PORT"])
        return s
