from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lumendrop.config import SecurityPolicy
from lumendrop.logging_setup import SECRETS, sanitize_text
from lumendrop.netinfo import normalize_host
from lumendrop.paths import FolderRejected, is_acceptable_existing_name, safe_filename, validate_share_folder
from lumendrop.security.auth import LoginNonce, SessionStore, generate_pin
from lumendrop.security.detector import ThreatDetector, inspect_path, inspect_query
from lumendrop.security.filescan import classify_bytes, sniff_kind
from lumendrop.security.ratelimit import TokenBucketLimiter


@pytest.mark.parametrize("raw, expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\boot.ini", "boot.ini"),
    ("CON", "_CON"),
    ("lpt1.txt", "_lpt1.txt"),
    (".htaccess", "htaccess"),
    ("a‮gpj.exe", "a_gpj.exe"),
    ("", "file"),
    ("...", "file"),
    ("ok name (1).tar.gz", "ok name (1).tar.gz"),
])
def test_safe_filename(raw, expected):
    assert safe_filename(raw) == expected


def test_safe_filename_length_bound():
    name = safe_filename("a" * 1000 + ".txt")
    assert name.endswith(".txt") and len(name.encode()) <= 240


def test_existing_name_validation():
    assert is_acceptable_existing_name("normal.txt")
    for bad in ("../x", ".hidden", "a/b", "a\x00b", "a‮b", "..", ""):
        assert not is_acceptable_existing_name(bad)


def test_share_folder_guards(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    for target in (Path("/"), Path.home(), Path("/etc"), data, data / "inner", Path.home() / ".ssh" / "x"):
        with pytest.raises(FolderRejected):
            validate_share_folder(target, data)
    ok = tmp_path / "share"
    assert validate_share_folder(ok, data) == ok.resolve()


def test_detector_posterior_and_decay():
    detector = ThreatDetector(SecurityPolicy(threat_half_life=10))
    score = detector.accumulate("c", 4.0, now=0.0)
    assert not detector.should_ban(score)
    score = detector.accumulate("c", 5.0, now=0.0)
    assert detector.should_ban(score)
    assert not detector.should_ban(score, prior_shift=-2.5)
    detector.reset("c")
    detector.accumulate("d", 8.0, now=0.0)
    assert abs(detector.current("d", now=10.0) - 4.0) < 1e-6


def test_path_inspection_precision():
    assert not inspect_path(b"/files/my..file.txt")
    assert not inspect_path(b"/files/%E5%86%99%E7%9C%9F.txt")
    names = {s.name for s in inspect_path(b"/files/..%2fsecret")}
    assert "path_traversal" in names
    assert {s.name for s in inspect_path(b"/x%c0%ae%c0%ae/")} >= {"overlong_utf8"}
    assert {s.name for s in inspect_path(b"/a%00b")} >= {"null_byte"}


def test_query_inspection_context():
    assert not inspect_query(b"sort=newest&offset=0&limit=200", 4096)
    free_text = inspect_query(b"q=union+select+password+from+users", 4096)
    assert free_text and all(s.weight <= 1.0 for s in free_text)
    strict = inspect_query(b"x=%3Cscript%3Ealert(1)%3C/script%3E", 4096)
    assert any(s.name == "xss_pattern" and s.weight == 2.0 for s in strict)


def test_token_bucket():
    limiter = TokenBucketLimiter(capacity=2, refill_per_second=1)
    assert limiter.take("k", now=0) == 0
    assert limiter.take("k", now=0) == 0
    assert limiter.take("k", now=0) > 0
    assert limiter.take("k", now=1.01) == 0


def test_session_expiry_and_binding():
    store = SessionStore(SecurityPolicy(session_idle_seconds=1))
    token, _ = store.create("c", "ua")
    assert store.get(token, "ua") is not None
    assert store.get(token, "other") is None
    store._sessions[next(iter(store._sessions))].last_seen -= 5
    assert store.get(token, "ua") is None


def test_login_nonce():
    nonce = LoginNonce()
    value = nonce.issue()
    assert nonce.verify(value, value)
    assert not nonce.verify(value, value + "x")
    assert not nonce.verify("A" * 54, "A" * 54)


def test_pin_quality():
    for _ in range(200):
        pin = generate_pin(8)
        assert len(pin) == 8 and pin.isdigit() and len(set(pin)) >= 4


def test_sniffing():
    assert sniff_kind(b"\xca\xfe\xba\xbe\x00\x00\x00\x34") == "java_class"
    assert sniff_kind(b"\xca\xfe\xba\xbe\x00\x00\x00\x02") == "macho"
    assert sniff_kind(b"MZ this is just text that starts with MZ" + b" " * 40) != "pe"
    assert classify_bytes("script.sh", b"#!/bin/sh\necho").reasons == ("executable",)
    assert classify_bytes("readme.txt", b"#!/bin/sh\n").quarantined


def test_log_sanitization():
    SECRETS.add("98765432")
    text = sanitize_text("pin=98765432\r\nINJECTED line\x1b[31m")
    assert "98765432" not in text and "\n" not in text and "\x1b" not in text
    token = "Ab3" + "x" * 40
    assert token not in sanitize_text(f"value {token}")
    assert "very_long_but_plain_filename_without_digits_here.txt" in sanitize_text(
        "very_long_but_plain_filename_without_digits_here.txt")


def test_host_normalization():
    assert normalize_host("Example.LOCAL:8420") == "example.local"
    assert normalize_host("[::1]:8420") == "::1"
    assert normalize_host("evil.com@good") is None
    assert normalize_host("a b") is None


def test_logger_never_emits_pin(tmp_path):
    from lumendrop.logging_setup import build_logger

    SECRETS.add("13572468")
    logger = build_logger(tmp_path, None, logging.INFO, console=False)
    logger.warning("Login with %s", "13572468")
    for handler in logger.handlers:
        handler.flush()
    content = (tmp_path / "logs" / "lumendrop.log").read_text()
    assert "13572468" not in content and "[REDACTED]" in content


def test_generic_binary_not_flagged_but_hidden_elf_is():
    import os as _os

    assert not classify_bytes("firmware.bin", _os.urandom(4096)).quarantined
    assert classify_bytes("firmware.bin", b"\x7fELF" + b"\x00" * 60).quarantined
