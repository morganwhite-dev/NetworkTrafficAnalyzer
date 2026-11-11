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

    exported = rdpcap(io.BytesIO(authed.get("/api/export.pcap").content))
    assert len(exported) == 62

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
