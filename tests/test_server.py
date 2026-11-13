from __future__ import annotations

import hashlib
import logging
import re
import socket
import ssl

import httpx

from lumendrop.config import Settings
from lumendrop.logging_setup import build_logger
from lumendrop.server import ServerController


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_real_server_tls_roundtrip(tmp_path):
    data_dir = tmp_path / "data"
    share = tmp_path / "share"
    port = _free_port()
    settings = Settings(share_folder=share, host="127.0.0.1", port=port, use_https=True, data_dir=data_dir)
    logger = build_logger(data_dir, None, logging.INFO, console=False)
    controller = ServerController(settings, logger)
    assert controller.info.https_active and controller.info.fingerprint
    assert controller.start()
    try:
        base = f"https://127.0.0.1:{port}"
        with httpx.Client(base_url=base, verify=False, timeout=10) as client:
            assert client.get("/api/health").json() == {"status": "ok"}
            page = client.get("/login")
            assert "strict-transport-security" in page.headers
            nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
            assert any(c.name == "__Host-lumendrop_login" for c in client.cookies.jar)
            response = client.post("/login", data={"pin": controller.ctx.pins.pin, "nonce": nonce})
            assert response.status_code == 303
            csrf = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/").text).group(1)
            client.headers["X-CSRF-Token"] = csrf
            payload = b"lumen" * 50_000
            init = client.post("/api/uploads", json={"filename": "net.bin", "total_size": len(payload)}).json()
            size = init["chunk_size"]
            for index in range(init["total_chunks"]):
                part = payload[index * size:(index + 1) * size]
                r = client.put(f"/api/uploads/{init['upload_id']}/chunks/{index}", content=part,
                               headers={"X-Chunk-SHA256": hashlib.sha256(part).hexdigest()})
                assert r.status_code == 200
            done = client.post(f"/api/uploads/{init['upload_id']}/complete").json()
            assert done["sha256"] == hashlib.sha256(payload).hexdigest()
            assert client.get("/files/net.bin").content == payload
            bad_host = client.get("/api/health", headers={"Host": "rebind.attacker.example"})
            assert bad_host.status_code == 421

        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname = False
        legacy.verify_mode = ssl.CERT_NONE
        legacy.maximum_version = ssl.TLSVersion.TLSv1_1
        legacy.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        refused = False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with legacy.wrap_socket(raw):
                    pass
        except (ssl.SSLError, OSError):
            refused = True
        assert refused
    finally:
        controller.stop()
    assert not controller.running


def test_port_conflict_reports_failure(tmp_path):
    data_dir = tmp_path / "data"
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        settings = Settings(share_folder=tmp_path / "share", host="127.0.0.1", port=port, use_https=False,
                            data_dir=data_dir)
        controller = ServerController(settings, build_logger(data_dir, None, logging.INFO, console=False))
        assert controller.start(timeout=5) is False
        controller.stop()
    finally:
        blocker.close()
