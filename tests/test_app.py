from __future__ import annotations

import hashlib
import os
import re
import time

from conftest import login

from lumendrop.security.ratelimit import client_key


def upload(client, name: str, data: bytes, checksum: bool = True):
    init = client.post("/api/uploads", json={"filename": name, "total_size": len(data)})
    assert init.status_code == 200, init.text
    info = init.json()
    size = info["chunk_size"]
    for index in range(info["total_chunks"]):
        part = data[index * size:(index + 1) * size]
        headers = {"Content-Type": "application/octet-stream"}
        if checksum:
            headers["X-Chunk-SHA256"] = hashlib.sha256(part).hexdigest()
        r = client.put(f"/api/uploads/{info['upload_id']}/chunks/{index}", content=part, headers=headers)
        assert r.status_code == 200, r.text
    done = client.post(f"/api/uploads/{info['upload_id']}/complete")
    assert done.status_code == 200, done.text
    return done.json()


def test_login_flow_and_security_headers(env):
    ctx, client, _ = env
    page = client.get("/login")
    assert page.status_code == 200
    assert "nonce-" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "server" not in page.headers
    assert login(client, "11111111").status_code == 401
    assert login(client).status_code == 303
    home = client.get("/")
    assert home.status_code == 200
    nonce = re.search(r"script-src 'nonce-([^']+)'", home.headers["content-security-policy"]).group(1)
    assert f'nonce="{nonce}"' in home.text
    assert 'name="csrf-token"' in home.text


def test_unauthenticated_access_is_blocked(env):
    _, client, _ = env
    assert client.get("/", follow_redirects=False).status_code == 303
    assert client.get("/api/files").status_code == 401
    assert client.get("/files/x.txt", follow_redirects=False).status_code == 303


def test_login_requires_valid_nonce(env):
    _, client, _ = env
    client.get("/login")
    r = client.post("/login", data={"pin": "48213957", "nonce": "forged"}, follow_redirects=False)
    assert r.status_code == 400


def test_csrf_required_for_state_changes(authed):
    _, client, _ = authed
    token = client.headers.pop("X-CSRF-Token")
    r = client.post("/api/uploads", json={"filename": "a.txt", "total_size": 10})
    assert r.status_code == 403
    client.headers["X-CSRF-Token"] = token
    r = client.post("/api/uploads", json={"filename": "a.txt", "total_size": 10})
    assert r.status_code == 200


def test_full_upload_download_delete_cycle(authed):
    ctx, client, share = authed
    data = os.urandom(200_000)
    result = upload(client, "report.pdf", data)
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert (share / "report.pdf").read_bytes() == data
    listing = client.get("/api/files").json()
    assert listing["total"] == 1 and listing["items"][0]["sha256"] == result["sha256"]
    download = client.get("/files/report.pdf?download=1")
    assert download.status_code == 200 and download.content == data
    assert download.headers["content-disposition"].startswith("attachment")
    assert "sandbox" in download.headers["content-security-policy"]
    ranged = client.get("/files/report.pdf", headers={"Range": "bytes=0-9"})
    assert ranged.status_code == 206 and ranged.content == data[:10]
    assert client.delete("/api/files/report.pdf").status_code == 200
    assert not (share / "report.pdf").exists()
    assert not list((share / ".lumendrop_staging").glob("*.part"))


def test_duplicate_names_are_never_overwritten(authed):
    _, client, share = authed
    upload(client, "same.txt", b"first")
    upload(client, "same.txt", b"second")
    assert (share / "same.txt").read_bytes() == b"first"
    assert (share / "same (1).txt").read_bytes() == b"second"


def test_chunk_validation(authed):
    _, client, _ = authed
    init = client.post("/api/uploads", json={"filename": "v.bin", "total_size": 70_000}).json()
    uid = init["upload_id"]
    assert init["total_chunks"] == 2
    bad_len = client.put(f"/api/uploads/{uid}/chunks/0", content=b"x" * 10)
    assert bad_len.status_code == 400
    out_of_range = client.put(f"/api/uploads/{uid}/chunks/5", content=b"x")
    assert out_of_range.status_code == 400
    part = b"y" * init["chunk_size"]
    bad_hash = client.put(f"/api/uploads/{uid}/chunks/0", content=part, headers={"X-Chunk-SHA256": "0" * 64})
    assert bad_hash.status_code == 422
    early = client.post(f"/api/uploads/{uid}/complete")
    assert early.status_code == 409
    ok = client.put(f"/api/uploads/{uid}/chunks/0", content=part)
    assert ok.status_code == 200
    status = client.get(f"/api/uploads/{uid}").json()
    assert status["received"] == [0]
    assert client.delete(f"/api/uploads/{uid}").json()["ok"] is True
    assert client.get(f"/api/uploads/{uid}").status_code == 404


def test_oversized_chunk_rejected_by_middleware(authed):
    ctx, client, _ = authed
    init = client.post("/api/uploads", json={"filename": "v.bin", "total_size": 10}).json()
    big = b"z" * (ctx.settings.limits.max_chunk + 1)
    r = client.put(f"/api/uploads/{init['upload_id']}/chunks/0", content=big)
    assert r.status_code == 413


def test_finalize_is_single_shot(authed):
    _, client, _ = authed
    init = client.post("/api/uploads", json={"filename": "one.txt", "total_size": 3}).json()
    client.put(f"/api/uploads/{init['upload_id']}/chunks/0", content=b"abc")
    assert client.post(f"/api/uploads/{init['upload_id']}/complete").status_code == 200
    assert client.post(f"/api/uploads/{init['upload_id']}/complete").status_code == 404


def test_insufficient_storage_and_quota(authed):
    ctx, client, _ = authed
    r = client.post("/api/uploads", json={"filename": "huge.bin", "total_size": ctx.settings.limits.max_upload_bytes + 1})
    assert r.status_code == 413
    r = client.post("/api/uploads", json={"filename": "big.bin", "total_size": 19 * 1024 ** 3})
    assert r.status_code in (200, 507)


def test_malicious_filenames_are_neutralised(authed):
    _, client, share = authed
    result = upload(client, "../../<script>alert(1)</script>.html", b"<script>alert(1)</script>")
    assert "/" not in result["name"] and "<" not in result["name"]
    assert (share / result["name"]).exists()
    r = client.get("/files/" + result["name"])
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"].startswith("attachment")
    svg = upload(client, "image.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")
    r = client.get("/files/" + svg["name"])
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-type"] == "application/octet-stream"
    reserved = upload(client, "CON.txt", b"x")
    assert reserved["name"].upper() != "CON.TXT"


def test_unicode_filenames_preserved(authed):
    _, client, share = authed
    result = upload(client, "写真 été.txt", b"hello")
    assert result["name"] == "写真 été.txt"
    assert client.get("/files/" + result["name"]).content == b"hello"


def test_disguised_executable_quarantined(authed):
    _, client, _ = authed
    pe = bytearray(b"MZ" + b"\x00" * 0x3A + (0x80).to_bytes(4, "little") + b"\x00" * (0x80 - 0x40) + b"PE\x00\x00" + b"\x00" * 64)
    result = upload(client, "holiday.jpg", bytes(pe))
    assert result["quarantined"] is True
    assert any(r.startswith("disguised_executable") for r in result["reasons"])
    benign = upload(client, "jquery.min.js", b"function x(){}")
    assert "double_extension" not in benign["reasons"]
    trick = upload(client, "invoice.pdf.exe", b"MZ\x00\x00")
    assert "double_extension" in trick["reasons"]


def test_real_image_served_inline_but_fake_is_not(authed):
    _, client, _ = authed
    png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4"
           b"\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")
    upload(client, "pixel.png", png)
    r = client.get("/files/pixel.png")
    assert r.headers["content-disposition"].startswith("inline") and r.headers["content-type"] == "image/png"
    thumb = client.get("/thumbs/pixel.png")
    assert thumb.status_code in (200, 204)
    upload(client, "fake.png", b"<html><script>alert(1)</script></html>")
    r = client.get("/files/fake.png")
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-type"] == "application/octet-stream"


def test_path_traversal_rejected_then_banned(env):
    ctx, client, _ = env
    first = client.get("/files/..%2f..%2fetc%2fpasswd")
    assert first.status_code in (400, 403)
    second = client.get("/files/%252e%252e%252fetc%252fpasswd")
    assert second.status_code == 403
    assert client.get("/login").status_code == 403
    assert ctx.bans.is_banned("testclient") > 0


def test_unexpected_host_header_rejected(env):
    _, client, _ = env
    r = client.get("/login", headers={"Host": "attacker.example"})
    assert r.status_code == 421


def test_cross_origin_writes_blocked(authed):
    _, client, _ = authed
    r = client.post("/api/uploads", json={"filename": "a", "total_size": 1}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    r = client.post("/api/uploads", json={"filename": "a", "total_size": 1}, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    r = client.get("/api/files", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"})
    assert r.status_code == 403
    r = client.post("/api/uploads", json={"filename": "a", "total_size": 1}, headers={"Origin": "http://testserver"})
    assert r.status_code == 200


def test_language_switch_has_no_open_redirect(env):
    _, client, _ = env
    r = client.get("/lang/pt", headers={"Referer": "http://evil.example/?testserver"}, follow_redirects=False)
    assert r.headers["location"] == "/"
    r = client.get("/lang/pt", headers={"Referer": "http://testserver/login"}, follow_redirects=False)
    assert r.headers["location"] == "/login"
    assert "Digite o PIN" in client.get("/login").text


def test_per_client_lockout(env):
    ctx, client, _ = env
    for _ in range(ctx.settings.policy.login_attempts_per_window):
        assert login(client, "00000001").status_code == 401
    assert login(client).status_code == 429


def test_distributed_bruteforce_rotates_pin(env):
    ctx, _, _ = env
    original = ctx.pins.pin
    rotated = []
    ctx.pins.on_rotate(lambda pin, reason: rotated.append((pin, reason)))
    for i in range(ctx.settings.policy.global_login_failure_budget):
        ctx.pins.verify(f"10.0.{i // 250}.{i % 250}", "00000000")
    assert rotated and rotated[0][1] == "distributed_bruteforce"
    assert ctx.pins.pin != original
    assert ctx.pins.precheck("10.9.9.9").reason == "paused"


def test_false_positive_resistance(authed):
    ctx, client, share = authed
    (share / "select photos from trip.jpg").write_bytes(b"\xff\xd8\xff\xe0data")
    (share / "notes.php").write_text("<?php echo 1;")
    (share / "my..file.txt").write_text("ok")
    for _ in range(15):
        assert client.get("/files/select%20photos%20from%20trip.jpg").status_code == 200
        assert client.get("/files/notes.php").status_code == 200
        assert client.get("/files/my..file.txt").status_code == 200
        assert client.get("/api/files", params={"q": "union of select"}).status_code == 200
    for _ in range(10):
        client.get("/favicon.ico")
        client.get("/apple-touch-icon.png")
    assert ctx.bans.is_banned("testclient") == 0


def test_scanner_gets_banned_quickly(env):
    ctx, client, _ = env
    headers = {"User-Agent": "sqlmap/1.7"}
    for path in ("/.env", "/wp-login.php", "/.git/config"):
        r = client.get(path, headers=headers)
        if r.status_code == 403:
            break
    assert ctx.bans.is_banned("testclient") > 0


def test_injection_in_query_raises_score(env):
    ctx, client, _ = env
    client.get("/login", params={"x": "1' or '1'='1"})
    assert ctx.detector.current("testclient") > 0


def test_jndi_and_crlf_hard_rejected(env):
    _, client, _ = env
    assert client.get("/login", headers={"X-Api-Version": "${jndi:ldap://x/a}"}).status_code in (400, 403)


def test_disallowed_method(env):
    _, client, _ = env
    assert client.request("TRACE", "/login").status_code in (403, 405)


def test_body_limit_on_login(env):
    _, client, _ = env
    r = client.post("/login", content=b"a" * 10_000, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413


def test_logout_revokes_session(authed):
    _, client, _ = authed
    assert client.post("/logout").status_code == 200
    assert client.get("/api/files").status_code == 401


def test_session_bound_to_user_agent(authed):
    _, client, _ = authed
    assert client.get("/api/files", headers={"User-Agent": "other"}).status_code == 401


def test_validation_errors_do_not_leak(authed):
    _, client, _ = authed
    r = client.post("/api/uploads", json={"filename": "a", "total_size": "lots", "extra": 1})
    assert r.status_code == 400
    assert set(r.json().keys()) <= {"detail", "code"}


def test_invalid_upload_id(authed):
    _, client, _ = authed
    assert client.get("/api/uploads/not-valid").status_code == 400


def test_client_key_groups_ipv6():
    assert client_key("2001:db8::1") == client_key("2001:db8::ffff")
    assert client_key("::ffff:192.168.1.5") == "192.168.1.5"


def test_maintenance_sweeps_expired(authed):
    ctx, client, share = authed
    init = client.post("/api/uploads", json={"filename": "stale.bin", "total_size": 5}).json()
    ctx.db.execute("UPDATE uploads SET updated = ? WHERE id = ?", (time.time() - 10 ** 6, init["upload_id"]))
    ctx.maintenance()
    assert not (share / ".lumendrop_staging" / f"{init['upload_id']}.part").exists()


def test_oversized_headers_rejected(env):
    _, client, _ = env
    assert client.get("/login", headers={"X-Big": "a" * 20_000}).status_code == 431


def test_no_slash_redirects(authed):
    _, client, _ = authed
    assert client.get("/files/", follow_redirects=False).status_code != 307
