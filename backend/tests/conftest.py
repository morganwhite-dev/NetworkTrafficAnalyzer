import io
import struct

import pytest
from fastapi.testclient import TestClient

from app.capture import LiveCapture
from app.config import Settings
from app.geoip import GeoResolver
from app.hub import Hub
from app.main import Runtime, create_app
from app.pipeline import Pipeline

TOKEN = "test-token-123"
ORIGIN = "http://127.0.0.1:8000"


def pcap_bytes(packets, start=1_700_000_000.0, step=0.01) -> bytes:
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for i, p in enumerate(packets):
        raw = bytes(p)
        ts = start + i * step
        sec = int(ts)
        buf.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(raw), len(raw)))
        buf.write(raw)
    return buf.getvalue()


@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.token = TOKEN
    s.port = 8000
    s.geo = "off"
    s.data_dir = tmp_path / "data"
    return s


@pytest.fixture
def runtime(settings):
    geo = GeoResolver("off", settings.geo_db, settings.data_dir)
    pipe = Pipeline(settings, geo)
    rt = Runtime(settings, geo, pipe, LiveCapture(pipe, settings.port), Hub(pipe))
    yield rt
    pipe.close()


@pytest.fixture
def client(runtime):
    app = create_app(runtime)
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        yield c


@pytest.fixture
def authed(client):
    client.cookies.set("nta_session", TOKEN)
    return client
