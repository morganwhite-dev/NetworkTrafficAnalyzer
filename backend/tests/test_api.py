import gzip
import io

import pytest
from conftest import ORIGIN, TOKEN, pcap_bytes
from scapy.all import rdpcap
from starlette.websockets import WebSocketDisconnect

from helpers import SELF, dns_answer, tcp

WS = "ws://127.0.0.1:8000/ws"
POST_HEADERS = {"origin": ORIGIN, "x-nta-request": "1"}


def sample_pcap():
    pkts = [dns_answer("github.com", "140.82.112.3")]
    pkts += [tcp(SELF, "140.82.112.3", 50000 + i, 443, "S") for i in range(60)]
    pkts.append(tcp(SELF, "93.184.215.14", 50100, 80, "PA",
                    b"POST /login HTTP/1.1\r\nHost: shop.example\r\n\r\nuser=a&password=hunter2"))
    return pcap_bytes(pkts)


def test_dashboard_locked_without_token(client):
    r = client.get("/")
    assert r.status_code == 401
    assert "link printed in the terminal" in r.text
    assert client.get("/api/status").status_code == 401


def test_token_link_sets_cookie_and_strips_url(client):
    r = client.get(f"/?t={TOKEN}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    client.cookies.clear()
    assert client.get("/?t=wrong", follow_redirects=False).status_code == 401


def test_security_headers(authed):
    r = authed.get("/api/status")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_dns_rebinding_host_rejected(authed):
    r = authed.get("/api/status", headers={"host": "evil.example:8000"})
    assert r.status_code == 400


def test_post_requires_origin_and_header(authed):
    assert authed.post("/api/clear").status_code == 403
    assert authed.post("/api/clear", headers={"origin": "http://evil.example"}).status_code == 403
    assert authed.post("/api/clear", headers={"origin": ORIGIN}).status_code == 403
    assert authed.post("/api/clear", headers=POST_HEADERS).status_code == 200


def test_websocket_checks_origin_and_cookie(client, authed):
    with pytest.raises(WebSocketDisconnect):
        with authed.websocket_connect(WS, headers={"origin": "http://evil.example"}) as ws:
            ws.receive_text()
    with authed.websocket_connect(WS, headers={"origin": ORIGIN}) as ws:
        snap = ws.receive_json()
        assert snap["type"] == "snapshot"
        assert snap["status"]["mode"] == "idle"


def test_upload_rejects_gzip_and_garbage(authed):
    gz = gzip.compress(sample_pcap())
    r = authed.post("/api/pcap", content=gz, headers=POST_HEADERS)
    assert r.status_code == 415
    r = authed.post("/api/pcap", content=b"not a pcap at all", headers=POST_HEADERS)
    assert r.status_code == 415


def test_upload_analyse_inspect_export(authed):
    r = authed.post("/api/pcap", content=sample_pcap(),
                    headers={**POST_HEADERS, "x-nta-filename": "sample.pcap"})
    assert r.status_code == 200, r.text
    assert r.json()["packets"] == 62
    status = authed.get("/api/status").json()
    assert status["mode"] == "file" and status["source"] == "sample.pcap"

    pkt = authed.get("/api/packets/62").json()
    assert pkt["row"]["proto"] == "HTTP"
    assert [layer["name"] for layer in pkt["layers"]][:3] == ["Ethernet", "IP", "TCP"]
    start, end = pkt["secrets"][0]
    assert bytes.fromhex(pkt["hex"])[start:end] == b"hunter2"
    assert "hunter2" not in str(pkt["layers"])        # masked in the decoded fields too

    exported = rdpcap(io.BytesIO(authed.get("/api/export.pcap").content))
    assert len(exported) == 62
    full_bytes = authed.get("/api/export.pcap").content
    assert b"hunter2" in full_bytes  # the full export keeps everything, as the dialog warns
    headers_only = authed.get("/api/export.pcap?headers_only=1").content
    assert b"hunter2" not in headers_only and b"POST /login" not in headers_only
    assert len(rdpcap(io.BytesIO(headers_only))) == 62

    with authed.websocket_connect(WS, headers={"origin": ORIGIN}) as ws:
        snap = ws.receive_json()
    creds = [a for a in snap["alerts"] if a["kind"] == "cleartext_credentials"]
    assert creds and creds[0]["severity"] == "critical"
    assert "hunter2" not in str(snap)
    secret = authed.post(f"/api/alerts/{creds[0]['id']}/reveal", headers=POST_HEADERS).json()
    assert secret["secret"] == "hunter2"


def test_unknown_interface_rejected(authed):
    r = authed.post("/api/capture/start", json={"iface": "nope0; rm -rf /"},
                    headers=POST_HEADERS)
    assert r.status_code == 400


def test_start_without_capture_permission_is_a_clear_403(authed):
    import os

    from scapy.all import get_if_list
    if os.geteuid() == 0:
        pytest.skip("running as root")
    from app.interfaces import capture_access
    if capture_access()[0]:
        pytest.skip("this machine can already capture (ChmodBPF)")
    iface = next(i for i in get_if_list() if i.startswith("lo"))
    r = authed.post("/api/capture/start", json={"iface": iface}, headers=POST_HEADERS)
    assert r.status_code == 403
    assert "sudo" in r.json()["detail"] or "CAP_NET_RAW" in r.json()["detail"]


def test_bundled_demo_toggles_on_demand(runtime, settings, tmp_path):
    """Live is the default; the Demo toggle starts the replay and Stop pauses it."""
    from fastapi.testclient import TestClient

    from app.config import DEMO_PCAP
    from app.main import create_app
    from app.pcapfile import normalize_in_child

    norm = tmp_path / "replay.pcap"
    normalize_in_child(DEMO_PCAP, norm, settings.max_file_packets, settings.max_record_bytes,
                       settings.pcap_parse_timeout)
    runtime.replay_file, runtime.replay_name = norm, DEMO_PCAP.name
    runtime.replay_auto, runtime.replay_loop = False, True

    with TestClient(create_app(runtime), base_url="http://127.0.0.1:8000") as c:
        c.cookies.set("nta_session", TOKEN)
        before = c.get("/api/status").json()
        assert before["mode"] != "replay" and not before["capturing"]  # nothing auto-started
        assert before["replay"] == "demo.pcap"                          # so the toggle is offered

        on = c.post("/api/capture/start", json={"iface": "replay"}, headers=POST_HEADERS).json()
        assert on["mode"] == "replay" and on["capturing"]
        assert runtime.replayer.loop is True
        assert "nta-demo-" in c.get("/api/export.pcap").headers["content-disposition"]

        off = c.post("/api/capture/stop", headers=POST_HEADERS).json()
        assert off["mode"] == "replay" and not off["capturing"]


def test_paused_replay_does_not_leak_a_packet_into_the_next_source(runtime, settings, tmp_path):
    """Switching away from the demo must not leak its last sleeping packet into the new session."""
    import time

    from app.capture import Replayer
    from app.config import DEMO_PCAP
    from app.pcapfile import normalize_in_child

    norm = tmp_path / "replay.pcap"
    normalize_in_child(DEMO_PCAP, norm, settings.max_file_packets, settings.max_record_bytes,
                       settings.pcap_parse_timeout)
    rp = Replayer(runtime.pipeline, norm, loop=True)
    rp.start()
    time.sleep(0.4)          # the thread is now in the middle of the demo
    rp.pause()
    runtime.pipeline.clear()  # what a switch to Live or a file does
    time.sleep(1.6)           # longer than the longest sleep between packets
    try:
        assert len(runtime.pipeline.store) == 0
    finally:
        rp.stop()


def test_empty_iface_never_means_demo(authed, runtime, settings, tmp_path):
    from app.config import DEMO_PCAP
    from app.pcapfile import normalize_in_child

    norm = tmp_path / "replay.pcap"
    normalize_in_child(DEMO_PCAP, norm, settings.max_file_packets, settings.max_record_bytes,
                       settings.pcap_parse_timeout)
    runtime.replay_file, runtime.replay_name = norm, DEMO_PCAP.name
    runtime.replay_auto = False
    runtime.live.iface = None
    for body in ({}, {"iface": ""}, {"iface": None}):
        r = authed.post("/api/capture/start", json=body, headers=POST_HEADERS)
        assert r.status_code == 400, body
    assert runtime.pipeline.mode != "replay"


def _demo_runtime(runtime, settings, tmp_path):
    from app.config import DEMO_PCAP
    from app.pcapfile import normalize_in_child

    norm = tmp_path / "replay.pcap"
    normalize_in_child(DEMO_PCAP, norm, settings.max_file_packets, settings.max_record_bytes,
                       settings.pcap_parse_timeout)
    runtime.replay_file, runtime.replay_name = norm, DEMO_PCAP.name
    runtime.replay_auto, runtime.replay_loop = False, True
    return runtime


def _loopback_iface():
    from scapy.all import get_if_list
    return next(i for i in get_if_list() if i.startswith("lo"))


def test_failed_live_switch_puts_the_demo_back(runtime, settings, tmp_path, monkeypatch):
    """Clicking Live without capture permission must not leave an empty, paused 'replay'."""
    from fastapi.testclient import TestClient

    from app.main import create_app

    _demo_runtime(runtime, settings, tmp_path)

    def denied(_iface):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(runtime.live, "start", denied)
    with TestClient(create_app(runtime), base_url="http://127.0.0.1:8000") as c:
        c.cookies.set("nta_session", TOKEN)
        c.post("/api/capture/start", json={"iface": "replay"}, headers=POST_HEADERS)
        r = c.post("/api/capture/start", json={"iface": _loopback_iface()},
                   headers=POST_HEADERS)
        assert r.status_code == 403
        st = c.get("/api/status").json()
        assert st["mode"] == "replay" and st["capturing"]        # the demo is playing again


def test_mode_switches_do_not_interleave(runtime, settings, tmp_path, monkeypatch):
    """A slow Live start and a Demo click at the same moment run one after the other."""
    import threading
    import time

    from fastapi.testclient import TestClient

    import app.main as main

    _demo_runtime(runtime, settings, tmp_path)
    events: list[str] = []

    def slow_live(_iface):
        events.append("live-begin")
        time.sleep(0.5)
        events.append("live-end")
        raise PermissionError("Permission denied")

    real_start_replay = main.start_replay

    def logged_replay(rt):
        events.append("demo")
        real_start_replay(rt)

    monkeypatch.setattr(runtime.live, "start", slow_live)
    monkeypatch.setattr(main, "start_replay", logged_replay)
    with TestClient(main.create_app(runtime), base_url="http://127.0.0.1:8000") as c:
        c.cookies.set("nta_session", TOKEN)
        iface = _loopback_iface()
        a = threading.Thread(target=lambda: c.post(
            "/api/capture/start", json={"iface": iface}, headers=POST_HEADERS))
        a.start()
        while "live-begin" not in events:
            time.sleep(0.01)
        b = threading.Thread(target=lambda: c.post(
            "/api/capture/start", json={"iface": "replay"}, headers=POST_HEADERS))
        b.start()
        a.join()
        b.join()
    assert events == ["live-begin", "live-end", "demo"]


def test_inspector_masks_a_secret_before_cutting_the_value_short(authed):
    """A Basic auth token that straddles the 160-character display cut must not half-show."""
    from helpers import tcp

    token = "dXNlcjpzdXBlcnNlY3JldHBhc3N3b3Jk"           # base64 of user:supersecretpassword
    body = (b"GET /" + b"a" * 80 + b" HTTP/1.1\r\nHost: shop.example\r\n"
            b"Authorization: Basic " + token.encode() + b"\r\n\r\n")
    pcap = pcap_bytes([tcp("192.168.1.23", "93.184.215.14", 51000, 80, "PA", body)])
    r = authed.post("/api/pcap", content=pcap, headers={**POST_HEADERS,
                                                         "x-nta-filename": "auth.pcap"})
    assert r.status_code == 200, r.text
    pkt = authed.get("/api/packets/1").json()
    assert pkt["secrets"], "the detector should have marked the token"
    shown = str(pkt["layers"])
    assert "dXNlcjpz" not in shown and "supersecret" not in shown


def test_other_local_pages_cannot_use_the_session_cookie(authed):
    """A page on another localhost port is same-site: it shares the cookie but not our trust."""
    for site in ("same-site", "cross-site", "none"):
        r = authed.get("/api/status", headers={"sec-fetch-site": site})
        assert r.status_code == 403, site
    assert authed.get("/api/status", headers={"sec-fetch-site": "same-origin"}).status_code == 200
    assert authed.get("/api/status").status_code == 200       # curl and other non-browsers
    with pytest.raises(WebSocketDisconnect):
        with authed.websocket_connect(
                WS, headers={"origin": ORIGIN, "sec-fetch-site": "same-site"}) as ws:
            ws.receive_text()
    with authed.websocket_connect(
            WS, headers={"origin": ORIGIN, "sec-fetch-site": "same-origin"}) as ws:
        assert ws.receive_json()["type"] == "snapshot"


def test_short_tokens_are_refused(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("NTA_TOKEN", "shots")
    with pytest.raises(ValueError, match="at least 16"):
        Settings.from_env()
    monkeypatch.setenv("NTA_TOKEN", "x" * 16)
    assert Settings.from_env().token == "x" * 16


def test_exports_say_where_the_data_came_from(authed):
    authed.post("/api/pcap", content=sample_pcap(),
                headers={**POST_HEADERS, "x-nta-filename": "sample.pcap"})
    disp = authed.get("/api/export.pcap").headers["content-disposition"]
    assert "nta-file-" in disp                      # an uploaded capture


def test_drop_target_prefers_sudo_then_container_settings(monkeypatch):
    from app.privileges import PrivilegeError, drop_target

    for k in ("SUDO_UID", "SUDO_GID", "NTA_DROP_UID", "NTA_DROP_GID"):
        monkeypatch.delenv(k, raising=False)
    assert drop_target() is None
    monkeypatch.setenv("NTA_DROP_UID", "10001")
    assert drop_target() is None                      # both halves are needed
    monkeypatch.setenv("NTA_DROP_GID", "10001")
    assert drop_target() == (10001, 10001)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    assert drop_target() == (501, 20)                 # sudo wins
    for bad in (("0", "20"), ("501", "0"), ("abc", "20")):
        monkeypatch.setenv("SUDO_UID", bad[0])
        monkeypatch.setenv("SUDO_GID", bad[1])
        with pytest.raises(PrivilegeError):
            drop_target()


def test_drop_does_nothing_when_not_root(monkeypatch):
    import os

    from app.privileges import drop_to_sudo_user

    if os.geteuid() == 0:
        pytest.skip("running as root")
    monkeypatch.setenv("NTA_DROP_UID", "10001")
    monkeypatch.setenv("NTA_DROP_GID", "10001")
    assert drop_to_sudo_user() is None
