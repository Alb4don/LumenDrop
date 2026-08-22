from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import html
import ipaddress
import json
import logging
import logging.handlers
import mimetypes
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import qrcode
import uvicorn
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

APP_NAME = "LumenDrop"
APP_VERSION = "1.1.0"
DEFAULT_PORT = 8420
SESSION_COOKIE = "lumendrop_session"
LANG_COOKIE = "lumendrop_lang"
SESSION_MAX_AGE = 60 * 60 * 12
MAX_UPLOAD_BYTES = 20 * 1024 * 1024 * 1024
UPLOAD_CHUNK_SIZE = 1024 * 1024
MAX_FILENAME_LENGTH = 180
PIN_LENGTH = 6
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900
GLOBAL_RATE_LIMIT_PER_MIN = 240
THREAT_BAN_SECONDS = 1800
THREAT_SCORE_BAN_THRESHOLD = 6
BAN_ESCALATION_MULTIPLIERS = (1, 4, 48)
TRUSTED_REPUTATION_MARGIN = 2
CUMULATIVE_THREAT_WINDOW_SECONDS = 300
CUMULATIVE_THREAT_THRESHOLD = 10
SECURITY_EVENT_RETENTION_DAYS = 30

RESUMABLE_MIN_CHUNK_SIZE = 256 * 1024
RESUMABLE_MAX_CHUNK_SIZE = 64 * 1024 * 1024
RESUMABLE_DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
UPLOAD_SESSION_TTL_SECONDS = 60 * 60 * 24
STAGING_DIR_NAME = ".lumendrop_staging"

CERT_VALIDITY_DAYS = 397

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".svg", ".avif"}
EXECUTABLE_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".js", ".jar",
    ".scr", ".com", ".dll", ".apk", ".app", ".pkg", ".deb", ".rpm", ".bin",
}
MAGIC_SIGNATURES = {
    b"MZ": "pe_executable",
    b"\x7fELF": "elf_executable",
    b"\xca\xfe\xba\xbe": "macho_or_class",
    b"\xfe\xed\xfa": "macho_executable",
}
SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9 ._\-\u00C0-\u017F]+")
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\.[/\\])|(%2e%2e)|(%00)|(\x00)", re.IGNORECASE)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(<\s*script)|(javascript:)|(on\w+\s*=)|(union\s+select)|(select\s+.+\s+from)|(--\s*$)",
    re.IGNORECASE,

)

STRINGS = {
    "en": {
        "page_title": "LumenDrop",
        "login_heading": "Enter Access PIN",
        "login_placeholder": "6-digit PIN",
        "login_button": "Unlock",
        "login_error": "Incorrect PIN. Try again.",
        "login_locked": "Too many attempts. Try again in {minutes} minute(s).",
        "logout": "Log out",
        "drop_zone_text": "Drag files here or tap to choose",
        "gallery_heading": "Shared files",
        "gallery_empty": "No files yet. Upload something to get started.",
        "download": "Download",
        "delete": "Delete",
        "delete_confirm": "Delete this file? This cannot be undone.",
        "uploaded_at": "Uploaded",
        "size_label": "Size",
        "quarantine_badge": "Unverified file type \u2014 check before opening",
        "language_label": "Language",
        "uploading": "Uploading",
        "done": "Done",
        "failed": "Failed",
        "forbidden": "Access denied.",
        "not_found": "The requested resource was not found.",
        "server_error": "Something went wrong. Please try again.",
        "rate_limited": "Too many requests. Please slow down.",
        "file_too_large": "File exceeds the maximum allowed size.",
        "invalid_filename": "Invalid file name.",
        "invalid_request": "The request is invalid.",
    },
    "pt": {
        "page_title": "LumenDrop",
        "login_heading": "Digite o PIN de acesso",
        "login_placeholder": "PIN de 6 d\u00edgitos",
        "login_button": "Desbloquear",
        "login_error": "PIN incorreto. Tente novamente.",
        "login_locked": "Muitas tentativas. Tente novamente em {minutes} minuto(s).",
        "logout": "Sair",
        "drop_zone_text": "Arraste arquivos aqui ou toque para escolher",
        "gallery_heading": "Arquivos compartilhados",
        "gallery_empty": "Nenhum arquivo ainda. Envie algo para come\u00e7ar.",
        "download": "Baixar",
        "delete": "Excluir",
        "delete_confirm": "Excluir este arquivo? Esta a\u00e7\u00e3o n\u00e3o pode ser desfeita.",
        "uploaded_at": "Enviado em",
        "size_label": "Tamanho",
        "quarantine_badge": "Tipo de arquivo n\u00e3o verificado \u2014 confira antes de abrir",
        "language_label": "Idioma",
        "uploading": "Enviando",
        "done": "Conclu\u00eddo",
        "failed": "Falhou",
        "forbidden": "Acesso negado.",
        "not_found": "O recurso solicitado n\u00e3o foi encontrado.",
        "server_error": "Algo deu errado. Tente novamente.",
        "rate_limited": "Muitas solicita\u00e7\u00f5es. Diminua o ritmo.",
        "file_too_large": "O arquivo excede o tamanho m\u00e1ximo permitido.",
        "invalid_filename": "Nome de arquivo inv\u00e1lido.",
        "invalid_request": "A solicita\u00e7\u00e3o \u00e9 inv\u00e1lida.",
    },
}

GUI_STRINGS = {
    "en": {
        "window_title": "LumenDrop Control Panel",
        "tab_server": "Server",
        "tab_security": "Security",
        "tab_logs": "Logs",
        "folder_label": "Shared folder",
        "browse": "Browse",
        "port_label": "Port",
        "host_label": "Host / URL",
        "pin_label": "Access PIN",
        "start": "Start server",
        "stop": "Stop server",
        "status_stopped": "Stopped",
        "status_running": "Running",
        "status_starting": "Starting\u2026",
        "status_stopping": "Stopping\u2026",
        "qr_hint": "Scan this QR code from any device on the same network",
        "fingerprint_label": "TLS fingerprint",
        "https_unavailable": "HTTPS unavailable (cryptography package missing or cert generation failed). Serving over plain HTTP.",
        "language_label": "Language",
        "root_warning": "Running with administrator/root privileges is not recommended. Restart without elevated privileges, or pass --allow-root if you fully understand the risk.",
        "security_events_heading": "Recent security events",
        "banned_ips_heading": "Temporarily blocked addresses",
        "col_time": "Time",
        "col_ip": "Address",
        "col_reason": "Reason",
        "col_score": "Score",
        "col_until": "Blocked until",
        "logs_heading": "Live log",
        "clear_logs": "Clear view",
        "open_browser": "Open in browser",
        "copy_pin": "Copy PIN",
        "copied": "Copied!",
        "quit": "Quit",
        "confirm_quit_title": "Quit LumenDrop?",
        "confirm_quit_body": "The server is still running. Stop it and quit?",
    },
    "pt": {
        "window_title": "Painel de Controle do LumenDrop",
        "tab_server": "Servidor",
        "tab_security": "Seguran\u00e7a",
        "tab_logs": "Registros",
        "folder_label": "Pasta compartilhada",
        "browse": "Procurar",
        "port_label": "Porta",
        "host_label": "Endere\u00e7o / URL",
        "pin_label": "PIN de acesso",
        "start": "Iniciar servidor",
        "stop": "Parar servidor",
        "status_stopped": "Parado",
        "status_running": "Em execu\u00e7\u00e3o",
        "status_starting": "Iniciando\u2026",
        "status_stopping": "Parando\u2026",
        "qr_hint": "Escaneie este QR code em qualquer dispositivo na mesma rede",
        "fingerprint_label": "Impressão digital TLS",
        "https_unavailable": "HTTPS indisponível (pacote cryptography ausente ou falha ao gerar o certificado). Servindo via HTTP simples.",
        "language_label": "Idioma",
        "root_warning": "N\u00e3o \u00e9 recomendado executar como administrador/root. Reinicie sem privil\u00e9gios elevados ou use --allow-root se voc\u00ea entende os riscos.",
        "security_events_heading": "Eventos de seguran\u00e7a recentes",
        "banned_ips_heading": "Endere\u00e7os bloqueados temporariamente",
        "col_time": "Hora",
        "col_ip": "Endere\u00e7o",
        "col_reason": "Motivo",
        "col_score": "Pontua\u00e7\u00e3o",
        "col_until": "Bloqueado at\u00e9",
        "logs_heading": "Registro em tempo real",
        "clear_logs": "Limpar visualiza\u00e7\u00e3o",
        "open_browser": "Abrir no navegador",
        "copy_pin": "Copiar PIN",
        "copied": "Copiado!",
        "quit": "Sair",
        "confirm_quit_title": "Encerrar o LumenDrop?",
        "confirm_quit_body": "O servidor ainda est\u00e1 em execu\u00e7\u00e3o. Parar e sair?",
    },
}

def app_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    target = Path(base) / "LumenDrop"
    target.mkdir(parents=True, exist_ok=True)
    return target


class RedactionFilter(logging.Filter):
    _pin_pattern = re.compile(r"\b\d{6}\b")
    _cookie_pattern = re.compile(r"(session|cookie)=[^;&\s]+", re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        message = self._pin_pattern.sub("[REDACTED-PIN]", message)
        message = self._cookie_pattern.sub(r"\1=[REDACTED]", message)
        record.msg = message
        record.args = ()
        return True


class QueueLogHandler(logging.Handler):
    def __init__(self, sink: "queue.Queue[str]"):
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.put_nowait(self.format(record))
        except Exception:
            pass


def build_logger(gui_queue: "queue.Queue[str]" = None) -> logging.Logger:
    logger = logging.getLogger("lumendrop")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    log_dir = app_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "lumendrop.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    file_handler.addFilter(RedactionFilter())
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    console_handler.addFilter(RedactionFilter())
    logger.addHandler(console_handler)

    if gui_queue is not None:
        qh = QueueLogHandler(gui_queue)
        qh.setFormatter(fmt)
        qh.addFilter(RedactionFilter())
        logger.addHandler(qh)

    logger.propagate = False
    return logger


def safe_filename(raw_name: str) -> str:
    name = Path(raw_name.replace("\x00", "")).name
    name = SAFE_NAME_PATTERN.sub("_", name).strip().strip(".")
    if not name:
        name = "file"
    if len(name) > MAX_FILENAME_LENGTH:
        stem = Path(name).stem[:140]
        suffix = Path(name).suffix[:20]
        name = f"{stem}{suffix}"
    return name


def unique_destination(upload_dir: Path, filename: str) -> Path:
    candidate = upload_dir / filename
    if not candidate.exists():
        return candidate
    stem, suffix = Path(filename).stem, Path(filename).suffix
    counter = 1
    while True:
        candidate = upload_dir / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def resolve_upload_path(upload_dir: Path, raw_name: str) -> Optional[Path]:
    cleaned = safe_filename(raw_name)
    candidate = (upload_dir / cleaned).resolve()
    upload_dir_resolved = upload_dir.resolve()
    try:
        candidate.relative_to(upload_dir_resolved)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def read_magic_bytes(path: Path, length: int = 8) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(length)
    except OSError:
        return b""


def classify_upload(path: Path) -> dict:
    ext = path.suffix.lower()
    reasons = []
    score = 0
    if ext in EXECUTABLE_EXTENSIONS:
        reasons.append("executable_extension")
        score += 2
    stem_suffixes = [s.lower() for s in path.suffixes]
    if len(stem_suffixes) >= 2 and stem_suffixes[-1] in EXECUTABLE_EXTENSIONS:
        reasons.append("double_extension")
        score += 2
    magic = read_magic_bytes(path)
    for signature, label in MAGIC_SIGNATURES.items():
        if magic.startswith(signature):
            if ext not in EXECUTABLE_EXTENSIONS:
                reasons.append(f"magic_mismatch:{label}")
                score += 3
            break
    quarantined = score >= 2
    return {"quarantined": quarantined, "score": score, "reasons": reasons}


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(UPLOAD_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_threat_score(request_path: str, query_string: str, form_values: list[str]) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    haystacks = [request_path, query_string] + form_values
    for value in haystacks:
        if not value:
            continue
        if PATH_TRAVERSAL_PATTERN.search(value):
            score += 4
            reasons.append("path_traversal_pattern")
        if SCRIPT_INJECTION_PATTERN.search(value):
            score += 3
            reasons.append("script_or_sql_pattern")
        if len(value) > 2048:
            score += 2
            reasons.append("oversized_field")
        if "\x00" in value:
            score += 3
            reasons.append("null_byte")
    return score, sorted(set(reasons))


@dataclass
class SecurityEvent:
    timestamp: float
    ip: str
    reason: str
    score: int


class SecurityEventBus:
    def __init__(self, maxlen: int = 200):
        self._events: deque[SecurityEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._subscribers: list["queue.Queue[SecurityEvent]"] = []

    def publish(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)
            for sink in self._subscribers:
                try:
                    sink.put_nowait(event)
                except Exception:
                    pass

    def subscribe(self) -> "queue.Queue[SecurityEvent]":
        sink: "queue.Queue[SecurityEvent]" = queue.Queue()
        with self._lock:
            self._subscribers.append(sink)
        return sink

    def recent(self) -> list[SecurityEvent]:
        with self._lock:
            return list(self._events)


class BanStore:
    def __init__(self, event_bus: SecurityEventBus, logger: logging.Logger, persistent_store: "PersistentSecurityStore"):
        self._banned_until: dict[str, float] = {}
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._logger = logger
        self._persistent_store = persistent_store
        self._banned_until.update(persistent_store.load_active_bans())

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            until = self._banned_until.get(ip)
            if until is None:
                return False
            if until <= time.time():
                del self._banned_until[ip]
                return False
            return True

    def ban(self, ip: str, reason: str, score: int, seconds: int = THREAT_BAN_SECONDS) -> None:
        prior_offenses = self._persistent_store.offense_count(ip)
        multiplier_index = min(prior_offenses, len(BAN_ESCALATION_MULTIPLIERS) - 1)
        effective_seconds = seconds * BAN_ESCALATION_MULTIPLIERS[multiplier_index]
        until = time.time() + effective_seconds
        with self._lock:
            self._banned_until[ip] = until
        self._persistent_store.record_event(ip, reason, score)
        self._persistent_store.record_ban(ip, reason, score, until, prior_offenses + 1)
        self._logger.warning(
            "Blocking address %s for %ss (%s, score=%s, offense #%s)",
            ip, effective_seconds, reason, score, prior_offenses + 1,
        )
        self._event_bus.publish(SecurityEvent(time.time(), ip, reason, score))

    def snapshot(self) -> dict[str, float]:
        with self._lock:
            return dict(self._banned_until)


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                return False
            bucket.append(now)
            return True


class LoginAttemptTracker:
    def __init__(self, persistent_store: "PersistentSecurityStore"):
        self._persistent_store = persistent_store

    def register_failure(self, ip: str) -> int:
        return self._persistent_store.record_login_failure(ip)

    def clear(self, ip: str) -> None:
        self._persistent_store.record_login_success(ip)

    def seconds_until_unlocked(self, ip: str) -> int:
        return self._persistent_store.seconds_until_login_unlocked(ip)


class SessionManager:
    def __init__(self):
        self.secret_key = secrets.token_urlsafe(48)
        self.serializer = URLSafeTimedSerializer(self.secret_key, salt="lumendrop-session")

    def make_cookie_value(self) -> str:
        return self.serializer.dumps({"ok": True})

    def is_authenticated(self, request: Request) -> bool:
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return False
        try:
            data = self.serializer.loads(token, max_age=SESSION_MAX_AGE)
        except BadSignature:
            return False
        except Exception:
            return False
        return bool(data.get("ok"))


class MetadataStore:
    def __init__(self, upload_dir: Path):
        self.upload_dir = upload_dir
        self.path = upload_dir / ".lumendrop_metadata.json"
        self._lock = threading.Lock()

    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def set(self, filename: str, info: dict) -> None:
        with self._lock:
            data = self._read()
            data[filename] = info
            self._write(data)

    def get(self, filename: str) -> dict:
        with self._lock:
            return self._read().get(filename, {})

    def remove(self, filename: str) -> None:
        with self._lock:
            data = self._read()
            data.pop(filename, None)
            self._write(data)


class PersistentSecurityStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        self.prune_old()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    ip TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    score INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON security_events(ip, ts);

                CREATE TABLE IF NOT EXISTS bans (
                    ip TEXT PRIMARY KEY,
                    banned_until REAL NOT NULL,
                    reason TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    offense_count INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    successful_logins INTEGER NOT NULL DEFAULT 0,
                    violation_count INTEGER NOT NULL DEFAULT 0,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS login_failures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    ts REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_login_failures_ip_ts ON login_failures(ip, ts);
                """
            )
            self._conn.commit()

    def _touch_reputation(self, ip: str) -> None:
        now = time.time()
        self._conn.execute(
            "INSERT INTO ip_reputation (ip, successful_logins, violation_count, first_seen, last_seen) "
            "VALUES (?, 0, 0, ?, ?) ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen",
            (ip, now, now),
        )

    def record_event(self, ip: str, reason: str, score: int) -> None:
        with self._lock:
            self._touch_reputation(ip)
            self._conn.execute(
                "INSERT INTO security_events (ts, ip, reason, score) VALUES (?, ?, ?, ?)",
                (time.time(), ip, reason, score),
            )
            self._conn.execute(
                "UPDATE ip_reputation SET violation_count = violation_count + 1 WHERE ip = ?", (ip,)
            )
            self._conn.commit()

    def record_ban(self, ip: str, reason: str, score: int, until: float, offense_count: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO bans (ip, banned_until, reason, score, offense_count) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET banned_until = excluded.banned_until, "
                "reason = excluded.reason, score = excluded.score, offense_count = excluded.offense_count",
                (ip, until, reason, score, offense_count),
            )
            self._conn.commit()

    def load_active_bans(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, banned_until FROM bans WHERE banned_until > ?", (time.time(),)
            ).fetchall()
            return {ip: until for ip, until in rows}

    def offense_count(self, ip: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT violation_count FROM ip_reputation WHERE ip = ?", (ip,)
            ).fetchone()
            return int(row[0]) if row else 0

    def is_trusted(self, ip: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT successful_logins, violation_count FROM ip_reputation WHERE ip = ?", (ip,)
            ).fetchone()
            if row is None:
                return False
            successful_logins, violation_count = row
            return successful_logins > 0 and violation_count == 0

    def record_login_success(self, ip: str) -> None:
        with self._lock:
            self._touch_reputation(ip)
            self._conn.execute(
                "UPDATE ip_reputation SET successful_logins = successful_logins + 1 WHERE ip = ?", (ip,)
            )
            self._conn.execute("DELETE FROM login_failures WHERE ip = ?", (ip,))
            self._conn.commit()

    def record_login_failure(self, ip: str) -> int:
        with self._lock:
            now = time.time()
            self._touch_reputation(ip)
            self._conn.execute("INSERT INTO login_failures (ip, ts) VALUES (?, ?)", (ip, now))
            self._conn.execute(
                "UPDATE ip_reputation SET violation_count = violation_count + 1 WHERE ip = ?", (ip,)
            )
            self._conn.commit()
            cutoff = now - LOGIN_LOCKOUT_SECONDS
            row = self._conn.execute(
                "SELECT COUNT(*) FROM login_failures WHERE ip = ? AND ts > ?", (ip, cutoff)
            ).fetchone()
            return int(row[0])

    def seconds_until_login_unlocked(self, ip: str) -> int:
        with self._lock:
            now = time.time()
            cutoff = now - LOGIN_LOCKOUT_SECONDS
            rows = self._conn.execute(
                "SELECT ts FROM login_failures WHERE ip = ? AND ts > ? ORDER BY ts", (ip, cutoff)
            ).fetchall()
            if len(rows) < MAX_LOGIN_ATTEMPTS:
                return 0
            oldest_relevant_ts = rows[-MAX_LOGIN_ATTEMPTS][0]
            remaining = LOGIN_LOCKOUT_SECONDS - (now - oldest_relevant_ts)
            return max(0, int(remaining))

    def cumulative_score(self, ip: str, window_seconds: int) -> int:
        with self._lock:
            cutoff = time.time() - window_seconds
            row = self._conn.execute(
                "SELECT COALESCE(SUM(score), 0) FROM security_events WHERE ip = ? AND ts > ?", (ip, cutoff)
            ).fetchone()
            return int(row[0])

    def prune_old(self, retention_days: int = SECURITY_EVENT_RETENTION_DAYS) -> None:
        with self._lock:
            cutoff = time.time() - retention_days * 86400
            self._conn.execute("DELETE FROM security_events WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM bans WHERE banned_until < ?", (cutoff,))
            self._conn.execute("DELETE FROM login_failures WHERE ts < ?", (cutoff,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class UploadSessionStore:
    def __init__(self, upload_dir: Path):
        self.staging_root = upload_dir / STAGING_DIR_NAME
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _session_dir(self, upload_id: str) -> Path:
        return self.staging_root / upload_id

    def _meta_path(self, upload_id: str) -> Path:
        return self._session_dir(upload_id) / "meta.json"

    def _chunks_dir(self, upload_id: str) -> Path:
        return self._session_dir(upload_id) / "chunks"

    def _read_meta(self, upload_id: str) -> Optional[dict]:
        path = self._meta_path(upload_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _write_meta(self, upload_id: str, meta: dict) -> None:
        path = self._meta_path(upload_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta), encoding="utf-8")
        tmp.replace(path)

    def sweep_expired(self) -> None:
        with self._lock:
            if not self.staging_root.exists():
                return
            now = time.time()
            for entry in self.staging_root.iterdir():
                if not entry.is_dir():
                    continue
                meta = self._read_meta(entry.name)
                created_at = meta.get("created_at", 0) if meta else 0
                if meta is None or now - created_at > UPLOAD_SESSION_TTL_SECONDS:
                    shutil.rmtree(entry, ignore_errors=True)

    def create_session(self, filename: str, total_size: int, chunk_size: int) -> dict:
        upload_id = secrets.token_urlsafe(24)
        total_chunks = max(1, -(-total_size // chunk_size))
        meta = {
            "upload_id": upload_id,
            "filename": filename,
            "total_size": total_size,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "received": [],
            "created_at": time.time(),
        }
        with self._lock:
            (self._session_dir(upload_id) / "chunks").mkdir(parents=True, exist_ok=True)
            self._write_meta(upload_id, meta)
        return meta

    def get_session(self, upload_id: str) -> Optional[dict]:
        with self._lock:
            meta = self._read_meta(upload_id)
            if meta is None:
                return None
            if time.time() - meta.get("created_at", 0) > UPLOAD_SESSION_TTL_SECONDS:
                shutil.rmtree(self._session_dir(upload_id), ignore_errors=True)
                return None
            return meta

    def chunk_path(self, upload_id: str, chunk_index: int) -> Path:
        return self._chunks_dir(upload_id) / f"{chunk_index:08d}.part"

    def mark_received(self, upload_id: str, chunk_index: int) -> Optional[dict]:
        with self._lock:
            meta = self._read_meta(upload_id)
            if meta is None:
                return None
            received = set(meta["received"])
            received.add(chunk_index)
            meta["received"] = sorted(received)
            self._write_meta(upload_id, meta)
            return meta

    def discard(self, upload_id: str) -> None:
        with self._lock:
            shutil.rmtree(self._session_dir(upload_id), ignore_errors=True)


APP_CSS = """
:root {
  --bg: #0f1720; --panel: #17212b; --accent: #4da3ff; --accent-2: #37e6b0;
  --text: #e7edf3; --muted: #93a4b8; --danger: #ff6b6b; --border: #26333f;
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); min-height: 100vh; }
.container { max-width: 780px; margin: 0 auto; padding: 24px 16px 80px; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.topbar a { color: var(--muted); text-decoration: none; font-size: 14px; }
h1 { font-size: 22px; margin: 0; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 20px; }
.dropzone {
  border: 2px dashed var(--border); border-radius: 14px; padding: 40px 20px;
  text-align: center; color: var(--muted); cursor: pointer; margin-bottom: 24px;
  transition: border-color .15s, background .15s;
}
.dropzone.dragover { border-color: var(--accent); background: rgba(77,163,255,0.08); color: var(--text); }
.upload-row { display: flex; align-items: center; gap: 10px; padding: 8px 0; font-size: 13px; }
.upload-row progress { flex: 1; height: 8px; }
.gallery-heading { font-size: 16px; color: var(--muted); margin: 24px 0 12px; text-transform: uppercase; letter-spacing: .04em; }
.file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 14px; }
.file-card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.file-thumb { width: 100%; height: 100px; object-fit: cover; display: block; background: #0c141c; }
.file-icon { width: 100%; height: 100px; display: flex; align-items: center; justify-content: center; font-size: 34px; background: #0c141c; }
.file-body { padding: 10px; }
.file-name { font-size: 13px; word-break: break-word; margin-bottom: 4px; }
.file-meta { font-size: 11px; color: var(--muted); margin-bottom: 8px; }
.badge-quarantine { display: inline-block; font-size: 10px; color: var(--danger); border: 1px solid var(--danger); border-radius: 6px; padding: 2px 6px; margin-bottom: 6px; }
.file-actions { display: flex; gap: 6px; }
.file-actions a, .file-actions button {
  flex: 1; text-align: center; text-decoration: none; font-size: 12px; padding: 6px 4px;
  border-radius: 8px; border: 1px solid var(--border); background: #0c141c; color: var(--text); cursor: pointer;
}
.file-actions button.delete { color: var(--danger); }
.empty-state { color: var(--muted); text-align: center; padding: 30px 0; }
.login-wrap { display: flex; min-height: 90vh; align-items: center; justify-content: center; }
.login-card { width: 100%; max-width: 320px; text-align: center; }
.login-card input {
  width: 100%; font-size: 24px; letter-spacing: 8px; text-align: center; padding: 12px;
  border-radius: 10px; border: 1px solid var(--border); background: #0c141c; color: var(--text); margin: 16px 0;
}
.login-card button {
  width: 100%; padding: 12px; border-radius: 10px; border: none; background: var(--accent);
  color: #04121f; font-weight: 600; cursor: pointer; font-size: 15px;
}
.error-text { color: var(--danger); font-size: 13px; min-height: 18px; margin-top: 8px; }
.lang-switch a { color: var(--muted); margin-left: 10px; font-size: 12px; text-decoration: none; border-bottom: 1px dotted var(--muted); }
.lang-switch a.active { color: var(--accent-2); border-color: var(--accent-2); }
"""

APP_JS = """
function preventPageNavigation() {
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(function (ev) {
    document.body.addEventListener(ev, function (e) { e.preventDefault(); });
  });
}

var LUMENDROP_CHUNK_SIZE = 4 * 1024 * 1024;

function lumendropStorageKey(file) {
  return 'lumendrop_upload::' + file.name + '::' + file.size + '::' + (file.lastModified || 0);
}

function lumendropGetSavedId(file) {
  try {
    return window.localStorage.getItem(lumendropStorageKey(file));
  } catch (e) {
    return null;
  }
}

function lumendropSaveId(file, uploadId) {
  try {
    window.localStorage.setItem(lumendropStorageKey(file), uploadId);
  } catch (e) {}
}

function lumendropClearId(file) {
  try {
    window.localStorage.removeItem(lumendropStorageKey(file));
  } catch (e) {}
}

function postJSON(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Requested-With': 'LumenDropClient'},
    body: JSON.stringify(body)
  }).then(function (r) {
    if (!r.ok) throw new Error('request_failed');
    return r.json();
  });
}

function getJSON(url) {
  return fetch(url, {headers: {'X-Requested-With': 'LumenDropClient'}}).then(function (r) {
    if (!r.ok) throw new Error('not_found');
    return r.json();
  });
}

function uploadChunkXhr(uploadId, index, blob) {
  return new Promise(function (resolve, reject) {
    var xhr = new XMLHttpRequest();
    var fd = new FormData();
    fd.append('upload_id', uploadId);
    fd.append('chunk_index', String(index));
    fd.append('chunk', blob, 'chunk');
    xhr.addEventListener('load', function () {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText));
      } else {
        reject(new Error('chunk_failed'));
      }
    });
    xhr.addEventListener('error', function () { reject(new Error('chunk_failed')); });
    xhr.open('POST', '/upload/chunk');
    xhr.setRequestHeader('X-Requested-With', 'LumenDropClient');
    xhr.send(fd);
  });
}

function uploadFileChunked(file, bar, pctLabel, labels) {
  var totalChunks = Math.max(1, Math.ceil(file.size / LUMENDROP_CHUNK_SIZE));

  function updateProgress(doneCount) {
    var pct = Math.round((doneCount / totalChunks) * 100);
    bar.value = pct;
    pctLabel.textContent = pct + '%';
  }

  function sendRemaining(uploadId, alreadyReceived) {
    var receivedSet = {};
    alreadyReceived.forEach(function (i) { receivedSet[i] = true; });
    var doneCount = alreadyReceived.length;
    updateProgress(doneCount);

    function sendNext(index) {
      if (index >= totalChunks) {
        return fetch('/upload/complete/' + uploadId, {
          method: 'POST', headers: {'X-Requested-With': 'LumenDropClient'},
        }).then(function (r) {
          if (!r.ok) throw new Error('complete_failed');
          return r.json();
        }).then(function () {
          lumendropClearId(file);
          pctLabel.textContent = labels.done;
        });
      }
      if (receivedSet[index]) {
        return sendNext(index + 1);
      }
      var start = index * LUMENDROP_CHUNK_SIZE;
      var end = Math.min(file.size, start + LUMENDROP_CHUNK_SIZE);
      return uploadChunkXhr(uploadId, index, file.slice(start, end)).then(function () {
        doneCount += 1;
        updateProgress(doneCount);
        return sendNext(index + 1);
      });
    }

    return sendNext(0);
  }

  function startFresh() {
    return postJSON('/upload/init', {
      filename: file.name, total_size: file.size, chunk_size: LUMENDROP_CHUNK_SIZE,
    }).then(function (init) {
      lumendropSaveId(file, init.upload_id);
      return sendRemaining(init.upload_id, []);
    });
  }

  var savedId = lumendropGetSavedId(file);
  var flow = savedId
    ? getJSON('/upload/status/' + savedId).then(function (status) {
        return sendRemaining(savedId, status.received);
      }).catch(function () {
        lumendropClearId(file);
        return startFresh();
      })
    : startFresh();

  return flow.catch(function () {
    pctLabel.textContent = labels.failed;
  });
}

function initUploader(labels) {
  var dropzone = document.getElementById('dropzone');
  var fileInput = document.getElementById('fileInput');
  var progressList = document.getElementById('progressList');
  if (!dropzone) return;

  preventPageNavigation();

  dropzone.addEventListener('click', function (e) {
    if (e.target.tagName !== 'INPUT') fileInput.click();
  });
  dropzone.addEventListener('dragover', function () { dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', function () { dropzone.classList.remove('dragover'); });
  dropzone.addEventListener('drop', function (e) {
    dropzone.classList.remove('dragover');
    if (e.dataTransfer && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', function () {
    if (fileInput.files.length) handleFiles(fileInput.files);
  });

  function handleFiles(fileList) {
    var files = Array.prototype.slice.call(fileList);
    var uploads = files.map(function (file) {
      var row = document.createElement('div');
      row.className = 'upload-row';
      var label = document.createElement('span');
      label.textContent = file.name;
      var bar = document.createElement('progress');
      bar.max = 100; bar.value = 0;
      var pct = document.createElement('span');
      pct.textContent = '0%';
      row.appendChild(label); row.appendChild(bar); row.appendChild(pct);
      progressList.appendChild(row);
      return uploadFileChunked(file, bar, pct, labels);
    });
    Promise.all(uploads).then(function () {
      setTimeout(function () { window.location.reload(); }, 600);
    });
  }
}

function confirmDelete(formEl, message) {
  if (window.confirm(message)) formEl.submit();
  return false;
}
"""


def render_lang_switch(lang: str) -> str:
    links = []
    for code, label in (("en", "EN"), ("pt", "PT-BR")):
        cls = "active" if code == lang else ""
        links.append(f'<a class="{cls}" href="/lang/{code}">{label}</a>')
    return f'<span class="lang-switch">{"".join(links)}</span>'


def render_login_page(lang: str, error: str = "") -> str:
    t = STRINGS[lang]
    error_html = html.escape(error) if error else ""
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>{html.escape(t['page_title'])}</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<div class="container login-wrap">
  <div class="card login-card">
    <div class="topbar"><h1>{html.escape(t['page_title'])}</h1>{render_lang_switch(lang)}</div>
    <p>{html.escape(t['login_heading'])}</p>
    <form method="post" action="/login" autocomplete="off">
      <input type="password" inputmode="numeric" pattern="[0-9]*" maxlength="{PIN_LENGTH}"
             name="pin" placeholder="{html.escape(t['login_placeholder'])}" autofocus required>
      <button type="submit">{html.escape(t['login_button'])}</button>
    </form>
    <div class="error-text">{error_html}</div>
  </div>
</div>
</body>
</html>"""


def render_file_card(f: Path, lang: str, metadata: dict) -> str:
    t = STRINGS[lang]
    name = f.name
    name_escaped = html.escape(name)
    from urllib.parse import quote
    name_quoted = quote(name)
    stat = f.stat()
    size_text = human_size(stat.st_size)
    when_text = time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime))
    ext = f.suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        thumb_html = f'<img class="file-thumb" src="/files/{name_quoted}" alt="" loading="lazy">'
    else:
        thumb_html = '<div class="file-icon">&#128196;</div>'
    quarantined = metadata.get("quarantined", False)
    badge_html = f'<div class="badge-quarantine">{html.escape(t["quarantine_badge"])}</div>' if quarantined else ""
    return f"""<div class="file-card">
  {thumb_html}
  <div class="file-body">
    {badge_html}
    <div class="file-name">{name_escaped}</div>
    <div class="file-meta">{size_text} &middot; {when_text}</div>
    <div class="file-actions">
      <a href="/files/{name_quoted}">{html.escape(t['download'])}</a>
      <form method="post" action="/files/{name_quoted}/delete" onsubmit="return confirmDelete(this, {json.dumps(t['delete_confirm'])});">
        <button type="submit" class="delete">{html.escape(t['delete'])}</button>
      </form>
    </div>
  </div>
</div>"""


def render_gallery(files: list[Path], lang: str, metadata_store: MetadataStore) -> str:
    t = STRINGS[lang]
    if not files:
        return f'<div class="empty-state">{html.escape(t["gallery_empty"])}</div>'
    cards = [render_file_card(f, lang, metadata_store.get(f.name)) for f in files]
    return f'<div class="file-grid">{"".join(cards)}</div>'


def render_main_page(lang: str, files: list[Path], metadata_store: MetadataStore) -> str:
    t = STRINGS[lang]
    gallery_html = render_gallery(files, lang, metadata_store)
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>{html.escape(t['page_title'])}</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<div class="container">
  <div class="topbar">
    <h1>{html.escape(t['page_title'])}</h1>
    <div>{render_lang_switch(lang)} <a href="/logout">{html.escape(t['logout'])}</a></div>
  </div>
  <div class="dropzone" id="dropzone">
    <p>{html.escape(t['drop_zone_text'])}</p>
    <input type="file" id="fileInput" multiple style="display:none">
  </div>
  <div id="progressList"></div>
  <div class="gallery-heading">{html.escape(t['gallery_heading'])}</div>
  {gallery_html}
</div>
<script src="/assets/app.js"></script>
<script>
initUploader({{done: {json.dumps(t['done'])}, failed: {json.dumps(t['failed'])}}});
</script>
</body>
</html>"""


@dataclass
class AppState:
    upload_dir: Path
    pin: str
    logger: logging.Logger
    persistent_store: "PersistentSecurityStore" = None
    session_manager: SessionManager = field(default_factory=SessionManager)
    event_bus: SecurityEventBus = field(default_factory=SecurityEventBus)
    ban_store: BanStore = None
    login_tracker: LoginAttemptTracker = None
    global_limiter: SlidingWindowLimiter = field(
        default_factory=lambda: SlidingWindowLimiter(GLOBAL_RATE_LIMIT_PER_MIN, 60)
    )
    login_limiter: SlidingWindowLimiter = field(default_factory=lambda: SlidingWindowLimiter(20, 60))
    metadata_store: MetadataStore = None
    upload_session_store: UploadSessionStore = None
    https_enabled: bool = False

    def __post_init__(self):
        if self.persistent_store is None:
            self.persistent_store = PersistentSecurityStore(app_data_dir() / "security.db")
        if self.ban_store is None:
            self.ban_store = BanStore(self.event_bus, self.logger, self.persistent_store)
        if self.login_tracker is None:
            self.login_tracker = LoginAttemptTracker(self.persistent_store)
        if self.metadata_store is None:
            self.metadata_store = MetadataStore(self.upload_dir)
        if self.upload_session_store is None:
            self.upload_session_store = UploadSessionStore(self.upload_dir)


def client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host


def get_lang(request: Request) -> str:
    value = request.cookies.get(LANG_COOKIE, "en")
    return value if value in STRINGS else "en"


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, state: AppState):
        super().__init__(app)
        self.state = state

    async def dispatch(self, request: Request, call_next):
        ip = client_ip(request)
        state = self.state

        if state.ban_store.is_banned(ip):
            return JSONResponse({"detail": "forbidden"}, status_code=403)

        if not state.global_limiter.allow(ip):
            state.logger.warning("Rate limit exceeded for %s", ip)
            return JSONResponse({"detail": "rate_limited"}, status_code=429)

        trusted = state.persistent_store.is_trusted(ip)
        margin = TRUSTED_REPUTATION_MARGIN if trusted else 0

        query_string = request.url.query or ""
        score, reasons = request_threat_score(request.url.path, query_string, [])
        if request.method in ("POST", "PUT", "PATCH"):
            origin = request.headers.get("origin") or request.headers.get("referer") or ""
            if origin and request.base_url.hostname not in origin:
                score += 3
                reasons.append("origin_mismatch")

        if score >= THREAT_SCORE_BAN_THRESHOLD + margin:
            state.ban_store.ban(ip, ",".join(reasons) or "heuristic_threat_score", score)
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        elif score > 0:
            reason_str = ",".join(reasons)
            state.persistent_store.record_event(ip, reason_str, score)
            state.event_bus.publish(SecurityEvent(time.time(), ip, reason_str, score))
            state.logger.info("Elevated threat score %s for %s (%s)", score, ip, reasons)

            cumulative = state.persistent_store.cumulative_score(ip, CUMULATIVE_THREAT_WINDOW_SECONDS)
            if cumulative >= CUMULATIVE_THREAT_THRESHOLD + margin:
                state.ban_store.ban(ip, f"cumulative_threat_score:{cumulative}", cumulative)
                return JSONResponse({"detail": "forbidden"}, status_code=403)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"
        if state.https_enabled:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


class AuthRequired(Exception):
    pass


class UploadInitRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=MAX_FILENAME_LENGTH * 2)
    total_size: int = Field(gt=0, le=MAX_UPLOAD_BYTES)
    chunk_size: int = Field(
        default=RESUMABLE_DEFAULT_CHUNK_SIZE, ge=RESUMABLE_MIN_CHUNK_SIZE, le=RESUMABLE_MAX_CHUNK_SIZE,
    )


def finalize_uploaded_file(state: AppState, ip: str, destination: Path, total_written: int) -> None:
    classification = classify_upload(destination)
    state.metadata_store.set(destination.name, {
        "uploaded_at": time.time(),
        "sha256": sha256_of_file(destination),
        "quarantined": classification["quarantined"],
        "heuristics": classification["reasons"],
    })
    if classification["quarantined"]:
        state.logger.warning(
            "Upload flagged for review from %s: %s (%s)",
            ip, destination.name, classification["reasons"],
        )
        state.persistent_store.record_event(
            ip, f"quarantined_upload:{destination.name}", classification["score"],
        )
        state.event_bus.publish(SecurityEvent(
            time.time(), ip, f"quarantined_upload:{destination.name}", classification["score"],
        ))
    state.logger.info("Upload saved from %s: %s (%s)", ip, destination.name, human_size(total_written))


def create_app(state: AppState) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware, state=state)

    def require_auth(request: Request) -> None:
        if not state.session_manager.is_authenticated(request):
            raise AuthRequired()

    @app.exception_handler(AuthRequired)
    async def handle_auth_required(request: Request, exc: AuthRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(404)
    async def handle_not_found(request: Request, exc):
        lang = get_lang(request)
        return JSONResponse({"detail": STRINGS[lang]["not_found"]}, status_code=404)

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception):
        state.logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        lang = get_lang(request)
        return JSONResponse({"detail": STRINGS[lang]["server_error"]}, status_code=500)

    @app.get("/assets/app.css")
    async def assets_css():
        return Response(APP_CSS, media_type="text/css")

    @app.get("/assets/app.js")
    async def assets_js():
        return Response(APP_JS, media_type="application/javascript")

    @app.get("/lang/{code}")
    async def switch_lang(code: str, request: Request):
        if code not in STRINGS:
            code = "en"
        referer = request.headers.get("referer", "/")
        destination = referer if request.base_url.hostname in referer else "/"
        response = RedirectResponse(destination, status_code=303)
        response.set_cookie(
            LANG_COOKIE, code, max_age=60 * 60 * 24 * 365, samesite="strict", httponly=True,
            secure=state.https_enabled,
        )
        return response

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        lang = get_lang(request)
        return render_login_page(lang)

    @app.post("/login")
    async def login_submit(request: Request, pin: str = Form(...)):
        lang = get_lang(request)
        ip = client_ip(request)

        if not state.login_limiter.allow(ip):
            return HTMLResponse(render_login_page(lang, STRINGS[lang]["rate_limited"]), status_code=429)

        locked_seconds = state.login_tracker.seconds_until_unlocked(ip)
        if locked_seconds > 0:
            minutes = max(1, locked_seconds // 60)
            message = STRINGS[lang]["login_locked"].format(minutes=minutes)
            return HTMLResponse(render_login_page(lang, message), status_code=429)

        pin_clean = re.sub(r"\D", "", pin)[:PIN_LENGTH]
        if len(pin_clean) != PIN_LENGTH or not secrets.compare_digest(pin_clean, state.pin):
            failures = state.login_tracker.register_failure(ip)
            state.logger.warning("Failed login attempt from %s (%s/%s)", ip, failures, MAX_LOGIN_ATTEMPTS)
            if failures >= MAX_LOGIN_ATTEMPTS:
                state.persistent_store.record_event(ip, "login_bruteforce", failures)
                state.event_bus.publish(SecurityEvent(time.time(), ip, "login_bruteforce", failures))
            return HTMLResponse(render_login_page(lang, STRINGS[lang]["login_error"]), status_code=401)

        state.login_tracker.clear(ip)
        state.logger.info("Successful login from %s", ip)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            state.session_manager.make_cookie_value(),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            samesite="strict",
            secure=state.https_enabled,
        )
        return response

    @app.get("/logout")
    async def logout():
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request, _: None = Depends(require_auth)):
        lang = get_lang(request)
        files = sorted(
            (p for p in state.upload_dir.iterdir() if p.is_file() and not p.name.startswith(".")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return render_main_page(lang, files, state.metadata_store)

    @app.post("/upload")
    async def upload(request: Request, files: list[UploadFile] = File(...), _: None = Depends(require_auth)):
        ip = client_ip(request)
        saved = []
        for upload_file in files:
            cleaned = safe_filename(upload_file.filename or "file")
            destination = unique_destination(state.upload_dir, cleaned)
            total_written = 0
            aborted = False
            try:
                with destination.open("wb") as out:
                    while True:
                        chunk = await upload_file.read(UPLOAD_CHUNK_SIZE)
                        if not chunk:
                            break
                        total_written += len(chunk)
                        if total_written > MAX_UPLOAD_BYTES:
                            aborted = True
                            break
                        out.write(chunk)
            finally:
                await upload_file.close()

            if aborted:
                destination.unlink(missing_ok=True)
                state.logger.warning("Rejected oversized upload from %s: %s", ip, cleaned)
                continue

            finalize_uploaded_file(state, ip, destination, total_written)
            saved.append(destination.name)

        return JSONResponse({"ok": True, "saved": saved})

    @app.post("/upload/init")
    async def upload_init(payload: UploadInitRequest, request: Request, _: None = Depends(require_auth)):
        state.upload_session_store.sweep_expired()
        cleaned_name = safe_filename(payload.filename)
        session = state.upload_session_store.create_session(cleaned_name, payload.total_size, payload.chunk_size)
        state.logger.info(
            "Upload session started by %s: %s (%s, %s chunk(s))",
            client_ip(request), cleaned_name, human_size(payload.total_size), session["total_chunks"],
        )
        return JSONResponse({
            "upload_id": session["upload_id"],
            "chunk_size": session["chunk_size"],
            "total_chunks": session["total_chunks"],
        })

    @app.get("/upload/status/{upload_id}")
    async def upload_status(upload_id: str, request: Request, _: None = Depends(require_auth)):
        session = state.upload_session_store.get_session(upload_id)
        if session is None:
            lang = get_lang(request)
            return JSONResponse({"detail": STRINGS[lang]["not_found"]}, status_code=404)
        return JSONResponse({
            "received": session["received"],
            "total_chunks": session["total_chunks"],
            "chunk_size": session["chunk_size"],
            "filename": session["filename"],
        })

    @app.post("/upload/chunk")
    async def upload_chunk(
        request: Request,
        upload_id: str = Form(...),
        chunk_index: int = Form(...),
        chunk: UploadFile = File(...),
        _: None = Depends(require_auth),
    ):
        lang = get_lang(request)
        ip = client_ip(request)
        session = state.upload_session_store.get_session(upload_id)
        if session is None:
            return JSONResponse({"detail": STRINGS[lang]["not_found"]}, status_code=404)

        total_chunks = session["total_chunks"]
        if chunk_index < 0 or chunk_index >= total_chunks:
            return JSONResponse({"detail": STRINGS[lang]["invalid_request"]}, status_code=400)

        max_allowed = min(session["chunk_size"], RESUMABLE_MAX_CHUNK_SIZE) + 1024
        destination = state.upload_session_store.chunk_path(upload_id, chunk_index)
        total_written = 0
        aborted = False
        try:
            with destination.open("wb") as out:
                while True:
                    data = await chunk.read(UPLOAD_CHUNK_SIZE)
                    if not data:
                        break
                    total_written += len(data)
                    if total_written > max_allowed:
                        aborted = True
                        break
                    out.write(data)
        finally:
            await chunk.close()

        if aborted:
            destination.unlink(missing_ok=True)
            state.logger.warning("Rejected oversized chunk from %s for session %s", ip, upload_id)
            return JSONResponse({"detail": STRINGS[lang]["file_too_large"]}, status_code=400)

        updated = state.upload_session_store.mark_received(upload_id, chunk_index)
        if updated is None:
            destination.unlink(missing_ok=True)
            return JSONResponse({"detail": STRINGS[lang]["not_found"]}, status_code=404)

        complete = len(updated["received"]) >= updated["total_chunks"]
        return JSONResponse({
            "received_count": len(updated["received"]),
            "total_chunks": updated["total_chunks"],
            "complete": complete,
        })

    @app.post("/upload/complete/{upload_id}")
    async def upload_complete(upload_id: str, request: Request, _: None = Depends(require_auth)):
        lang = get_lang(request)
        ip = client_ip(request)
        session = state.upload_session_store.get_session(upload_id)
        if session is None:
            return JSONResponse({"detail": STRINGS[lang]["not_found"]}, status_code=404)

        total_chunks = session["total_chunks"]
        received = set(session["received"])
        if received != set(range(total_chunks)):
            return JSONResponse(
                {"detail": "incomplete", "received": sorted(received), "total_chunks": total_chunks},
                status_code=409,
            )

        destination = unique_destination(state.upload_dir, session["filename"])
        total_written = 0
        try:
            with destination.open("wb") as out:
                for index in range(total_chunks):
                    part_path = state.upload_session_store.chunk_path(upload_id, index)
                    with part_path.open("rb") as part:
                        while True:
                            block = part.read(UPLOAD_CHUNK_SIZE)
                            if not block:
                                break
                            total_written += len(block)
                            out.write(block)
        except OSError:
            destination.unlink(missing_ok=True)
            state.upload_session_store.discard(upload_id)
            return JSONResponse({"detail": STRINGS[lang]["server_error"]}, status_code=500)

        if total_written != session["total_size"]:
            destination.unlink(missing_ok=True)
            state.upload_session_store.discard(upload_id)
            state.logger.warning("Assembled size mismatch from %s for %s", ip, session["filename"])
            return JSONResponse({"detail": STRINGS[lang]["server_error"]}, status_code=400)

        finalize_uploaded_file(state, ip, destination, total_written)
        state.upload_session_store.discard(upload_id)
        return JSONResponse({"ok": True, "saved": destination.name})

    @app.get("/files/{name:path}")
    async def download(name: str, request: Request, _: None = Depends(require_auth)):
        target = resolve_upload_path(state.upload_dir, name)
        if target is None:
            lang = get_lang(request)
            return JSONResponse({"detail": STRINGS[lang]["not_found"]}, status_code=404)
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        headers = {"Content-Disposition": f'attachment; filename="{target.name}"'}
        return Response(target.read_bytes(), media_type=media_type, headers=headers)

    @app.post("/files/{name:path}/delete")
    async def delete_file(name: str, request: Request, _: None = Depends(require_auth)):
        target = resolve_upload_path(state.upload_dir, name)
        if target is not None:
            target.unlink(missing_ok=True)
            state.metadata_store.remove(target.name)
            state.logger.info("Deleted by %s: %s", client_ip(request), target.name)
        return RedirectResponse("/", status_code=303)

    return app


def detect_lan_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def is_elevated_privileges() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def generate_qr_image(data: str):
    qr = qrcode.QRCode(border=1, box_size=8)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def generate_pin() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(PIN_LENGTH))


def _cert_not_valid_after(cert) -> datetime.datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _cert_covers_ip(cert, lan_ip: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        covered_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    except x509.ExtensionNotFound:
        return False
    return lan_ip in covered_ips


def _write_private_key_file(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _build_self_signed_certificate(lan_ip: str) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, APP_NAME)])

    san_entries: list = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        ip_obj = ipaddress.ip_address(lan_ip)
        if str(ip_obj) not in {"127.0.0.1"}:
            san_entries.append(x509.IPAddress(ip_obj))
    except ValueError:
        san_entries.append(x509.DNSName(lan_ip))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, crypto_hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    return cert_bytes, key_bytes


def ensure_certificate(cert_dir: Path, lan_ip: str, logger: logging.Logger) -> Optional[tuple]:
    if not CRYPTOGRAPHY_AVAILABLE:
        logger.warning("The 'cryptography' package is not installed; HTTPS is unavailable this run.")
        return None

    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    needs_regeneration = not cert_path.exists() or not key_path.exists()
    existing_cert = None
    if not needs_regeneration:
        try:
            existing_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if _cert_not_valid_after(existing_cert) <= datetime.datetime.now(datetime.timezone.utc):
                needs_regeneration = True
            elif not _cert_covers_ip(existing_cert, lan_ip):
                needs_regeneration = True
        except (ValueError, OSError):
            needs_regeneration = True

    if needs_regeneration:
        logger.info("Generating a new self-signed TLS certificate for %s", lan_ip)
        cert_bytes, key_bytes = _build_self_signed_certificate(lan_ip)
        cert_path.write_bytes(cert_bytes)
        _write_private_key_file(key_path, key_bytes)
        existing_cert = x509.load_pem_x509_certificate(cert_bytes)

    fingerprint = existing_cert.fingerprint(crypto_hashes.SHA256())
    fingerprint_hex = ":".join(f"{b:02X}" for b in fingerprint)
    return cert_path, key_path, fingerprint_hex


class ServerController:
    def __init__(
        self,
        upload_dir: Path,
        host: str,
        port: int,
        pin: str,
        logger: logging.Logger,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
    ):
        self.upload_dir = upload_dir
        self.host = host
        self.port = port
        self.pin = pin
        self.logger = logger
        self.cert_path = cert_path
        self.key_path = key_path
        self.state = AppState(
            upload_dir=upload_dir, pin=pin, logger=logger, https_enabled=cert_path is not None,
        )
        self.app = create_app(self.state)
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        config_kwargs = dict(host=self.host, port=self.port, log_level="warning", access_log=False)
        if self.cert_path is not None and self.key_path is not None:
            config_kwargs["ssl_certfile"] = str(self.cert_path)
            config_kwargs["ssl_keyfile"] = str(self.key_path)
        config = uvicorn.Config(self.app, **config_kwargs)
        self._server = uvicorn.Server(config)

        def _run():
            self._server.run()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        deadline = time.time() + 5
        while time.time() < deadline and not getattr(self._server, "started", False):
            time.sleep(0.05)

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None
        self._server = None
        if self.state.persistent_store is not None:
            self.state.persistent_store.close()


def build_gui(
    initial_dir: Path, initial_port: int, allow_root: bool, use_https: bool,
    gui_logger: logging.Logger, gui_queue,
) -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText
    import ttkbootstrap as ttk
    from ttkbootstrap.constants import BOTH, X, LEFT, RIGHT, YES, W
    from PIL import ImageTk

    class LumenDropGUI:
        def __init__(self):
            self.lang = "en"
            self.upload_dir = initial_dir
            self.use_https = use_https
            self.controller: Optional[ServerController] = None
            self.event_queue = None
            self.log_queue = gui_queue
            self.qr_photo = None

            self.root = ttk.Window(themename="darkly")
            self.root.title(GUI_STRINGS[self.lang]["window_title"])
            self.root.geometry("760x680")
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)

            self.folder_var = tk.StringVar(value=str(initial_dir))
            self.port_var = tk.IntVar(value=initial_port)
            self.host_var = tk.StringVar(value="")
            self.pin_var = tk.StringVar(value="------")
            self.fingerprint_var = tk.StringVar(value="")
            self.status_var = tk.StringVar(value=GUI_STRINGS[self.lang]["status_stopped"])
            self.lang_var = tk.StringVar(value="English")

            self._build_layout()
            if is_elevated_privileges() and not allow_root:
                self._show_root_warning()
            self.root.after(200, self.poll_queues)

        def t(self, key: str) -> str:
            return GUI_STRINGS[self.lang][key]

        def _build_layout(self) -> None:
            top = ttk.Frame(self.root, padding=10)
            top.pack(fill=X)
            self.title_label = ttk.Label(top, text=self.t("window_title"), font=("TkDefaultFont", 14, "bold"))
            self.title_label.pack(side=LEFT)
            self.lang_label = ttk.Label(top, text=self.t("language_label"))
            self.lang_label.pack(side=RIGHT, padx=(0, 4))
            self.lang_combo = ttk.Combobox(
                top, textvariable=self.lang_var, values=["English", "Portugu\u00eas (BR)"],
                state="readonly", width=16,
            )
            self.lang_combo.pack(side=RIGHT)
            self.lang_combo.bind("<<ComboboxSelected>>", self.on_lang_change)

            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill=BOTH, expand=YES, padx=10, pady=10)

            self.tab_server = ttk.Frame(self.notebook, padding=14)
            self.tab_security = ttk.Frame(self.notebook, padding=14)
            self.tab_logs = ttk.Frame(self.notebook, padding=14)
            self.notebook.add(self.tab_server, text=self.t("tab_server"))
            self.notebook.add(self.tab_security, text=self.t("tab_security"))
            self.notebook.add(self.tab_logs, text=self.t("tab_logs"))

            self._build_server_tab()
            self._build_security_tab()
            self._build_logs_tab()

        def _build_server_tab(self) -> None:
            frame = self.tab_server
            self.folder_label = ttk.Label(frame, text=self.t("folder_label"))
            self.folder_label.grid(row=0, column=0, sticky=W, pady=6)
            entry = ttk.Entry(frame, textvariable=self.folder_var, width=44)
            entry.grid(row=0, column=1, sticky=W, padx=6)
            self.browse_button = ttk.Button(frame, text=self.t("browse"), command=self.on_browse)
            self.browse_button.grid(row=0, column=2, padx=6)

            self.port_label = ttk.Label(frame, text=self.t("port_label"))
            self.port_label.grid(row=1, column=0, sticky=W, pady=6)
            ttk.Spinbox(frame, from_=1024, to=65535, textvariable=self.port_var, width=10).grid(
                row=1, column=1, sticky=W, padx=6
            )

            self.host_label = ttk.Label(frame, text=self.t("host_label"))
            self.host_label.grid(row=2, column=0, sticky=W, pady=6)
            ttk.Entry(frame, textvariable=self.host_var, width=44, state="readonly").grid(
                row=2, column=1, sticky=W, padx=6
            )
            self.open_browser_button = ttk.Button(frame, text=self.t("open_browser"), command=self.on_open_browser)
            self.open_browser_button.grid(row=2, column=2, padx=6)

            self.pin_label = ttk.Label(frame, text=self.t("pin_label"))
            self.pin_label.grid(row=3, column=0, sticky=W, pady=6)
            ttk.Label(frame, textvariable=self.pin_var, font=("TkDefaultFont", 20, "bold")).grid(
                row=3, column=1, sticky=W, padx=6
            )
            self.copy_pin_button = ttk.Button(frame, text=self.t("copy_pin"), command=self.on_copy_pin)
            self.copy_pin_button.grid(row=3, column=2, padx=6)

            self.qr_label = ttk.Label(frame)
            self.qr_label.grid(row=4, column=0, columnspan=2, pady=12, sticky=W)
            self.qr_hint_label = ttk.Label(frame, text=self.t("qr_hint"))
            self.qr_hint_label.grid(row=5, column=0, columnspan=2, sticky=W)

            self.fingerprint_label = ttk.Label(frame, text=self.t("fingerprint_label"))
            self.fingerprint_label.grid(row=6, column=0, sticky=W, pady=6)
            ttk.Label(
                frame, textvariable=self.fingerprint_var, font=("TkDefaultFont", 9),
            ).grid(row=6, column=1, columnspan=2, sticky=W, padx=6)

            button_row = ttk.Frame(frame)
            button_row.grid(row=7, column=0, columnspan=3, pady=16, sticky=W)
            self.start_button = ttk.Button(button_row, text=self.t("start"), command=self.on_start, bootstyle="success")
            self.start_button.pack(side=LEFT, padx=(0, 8))
            self.stop_button = ttk.Button(
                button_row, text=self.t("stop"), command=self.on_stop, bootstyle="danger", state="disabled"
            )
            self.stop_button.pack(side=LEFT)

            self.status_label = ttk.Label(frame, textvariable=self.status_var, font=("TkDefaultFont", 10, "italic"))
            self.status_label.grid(row=8, column=0, columnspan=3, sticky=W, pady=(6, 0))

            self.root_warning_label = ttk.Label(frame, text="", bootstyle="danger", wraplength=680)
            self.root_warning_label.grid(row=9, column=0, columnspan=3, sticky=W, pady=(10, 0))

            self.https_warning_label = ttk.Label(frame, text="", bootstyle="warning", wraplength=680)
            self.https_warning_label.grid(row=10, column=0, columnspan=3, sticky=W, pady=(4, 0))

        def _build_security_tab(self) -> None:
            frame = self.tab_security
            self.security_events_heading = ttk.Label(frame, text=self.t("security_events_heading"), font=("TkDefaultFont", 11, "bold"))
            self.security_events_heading.pack(anchor=W)
            columns = ("time", "ip", "reason", "score")
            self.events_tree = ttk.Treeview(frame, columns=columns, show="headings", height=8)
            for col in columns:
                self.events_tree.heading(col, text=self.t(f"col_{col}"))
                self.events_tree.column(col, width=150)
            self.events_tree.pack(fill=X, pady=(4, 16))

            self.banned_heading = ttk.Label(frame, text=self.t("banned_ips_heading"), font=("TkDefaultFont", 11, "bold"))
            self.banned_heading.pack(anchor=W)
            ban_columns = ("ip", "until")
            self.banned_tree = ttk.Treeview(frame, columns=ban_columns, show="headings", height=6)
            for col in ban_columns:
                self.banned_tree.heading(col, text=self.t(f"col_{col}"))
                self.banned_tree.column(col, width=200)
            self.banned_tree.pack(fill=X, pady=4)

        def _build_logs_tab(self) -> None:
            frame = self.tab_logs
            self.logs_heading = ttk.Label(frame, text=self.t("logs_heading"), font=("TkDefaultFont", 11, "bold"))
            self.logs_heading.pack(anchor=W)
            self.log_text = ScrolledText(
                frame, height=22, wrap="word",
                background="#0c141c", foreground="#e7edf3", insertbackground="#e7edf3",
                borderwidth=0, highlightthickness=0,
            )
            self.log_text.pack(fill=BOTH, expand=YES, pady=(4, 8))
            self.log_text.configure(state="disabled")
            self.clear_logs_button = ttk.Button(frame, text=self.t("clear_logs"), command=self.on_clear_logs)
            self.clear_logs_button.pack(anchor=W)

        def _show_root_warning(self) -> None:
            self.root_warning_label.configure(text=self.t("root_warning"))

        def refresh_texts(self) -> None:
            g = GUI_STRINGS[self.lang]
            self.root.title(g["window_title"])
            self.title_label.configure(text=g["window_title"])
            self.lang_label.configure(text=g["language_label"])
            self.notebook.tab(self.tab_server, text=g["tab_server"])
            self.notebook.tab(self.tab_security, text=g["tab_security"])
            self.notebook.tab(self.tab_logs, text=g["tab_logs"])
            self.folder_label.configure(text=g["folder_label"])
            self.browse_button.configure(text=g["browse"])
            self.port_label.configure(text=g["port_label"])
            self.host_label.configure(text=g["host_label"])
            self.open_browser_button.configure(text=g["open_browser"])
            self.pin_label.configure(text=g["pin_label"])
            self.copy_pin_button.configure(text=g["copy_pin"])
            self.qr_hint_label.configure(text=g["qr_hint"])
            self.fingerprint_label.configure(text=g["fingerprint_label"])
            if self.https_warning_label.cget("text"):
                self.https_warning_label.configure(text=g["https_unavailable"])
            self.start_button.configure(text=g["start"])
            self.stop_button.configure(text=g["stop"])
            running = self.controller is not None and self.controller.running
            self.status_var.set(g["status_running"] if running else g["status_stopped"])
            if is_elevated_privileges() and not allow_root:
                self.root_warning_label.configure(text=g["root_warning"])
            self.security_events_heading.configure(text=g["security_events_heading"])
            self.banned_heading.configure(text=g["banned_ips_heading"])
            for col in ("time", "ip", "reason", "score"):
                self.events_tree.heading(col, text=g[f"col_{col}"])
            for col in ("ip", "until"):
                self.banned_tree.heading(col, text=g[f"col_{col}"])
            self.logs_heading.configure(text=g["logs_heading"])
            self.clear_logs_button.configure(text=g["clear_logs"])

        def on_lang_change(self, _event=None) -> None:
            self.lang = "en" if self.lang_var.get().startswith("English") else "pt"
            self.refresh_texts()

        def on_browse(self) -> None:
            chosen = filedialog.askdirectory(initialdir=self.folder_var.get())
            if chosen:
                self.folder_var.set(chosen)

        def on_open_browser(self) -> None:
            url = self.host_var.get()
            if url:
                webbrowser.open(url)

        def on_copy_pin(self) -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.pin_var.get())

        def on_clear_logs(self) -> None:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")

        def on_start(self) -> None:
            g = GUI_STRINGS[self.lang]
            folder = Path(self.folder_var.get()).expanduser()
            try:
                folder.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                messagebox.showerror(g["window_title"], str(exc))
                return

            pin = generate_pin()
            lan_ip = detect_lan_ip()

            cert_path = key_path = None
            fingerprint = None
            if self.use_https:
                cert_info = ensure_certificate(app_data_dir() / "tls", lan_ip, gui_logger)
                if cert_info is not None:
                    cert_path, key_path, fingerprint = cert_info

            scheme = "https" if cert_path is not None else "http"
            if self.use_https and cert_path is None:
                self.https_warning_label.configure(text=g["https_unavailable"])
            else:
                self.https_warning_label.configure(text="")

            self.controller = ServerController(
                upload_dir=folder, host="0.0.0.0", port=self.port_var.get(), pin=pin, logger=gui_logger,
                cert_path=cert_path, key_path=key_path,
            )
            self.event_queue = self.controller.state.event_bus.subscribe()
            self.status_var.set(g["status_starting"])
            self.root.update_idletasks()
            self.controller.start()

            url = f"{scheme}://{lan_ip}:{self.port_var.get()}/"
            self.host_var.set(url)
            self.pin_var.set(pin)
            self.fingerprint_var.set(fingerprint if fingerprint else "-")
            qr_image = generate_qr_image(url).resize((180, 180))
            self.qr_photo = ImageTk.PhotoImage(qr_image)
            self.qr_label.configure(image=self.qr_photo)

            self.status_var.set(g["status_running"])
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            gui_logger.info("Server started on %s (folder=%s)", url, folder)

        def on_stop(self) -> None:
            g = GUI_STRINGS[self.lang]
            if self.controller is None:
                return
            self.status_var.set(g["status_stopping"])
            self.root.update_idletasks()
            self.controller.stop()
            self.status_var.set(g["status_stopped"])
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            gui_logger.info("Server stopped")

        def refresh_security_tables(self) -> None:
            if self.controller is None:
                return
            for row in self.events_tree.get_children():
                self.events_tree.delete(row)
            for event in self.controller.state.event_bus.recent()[-50:][::-1]:
                when = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
                self.events_tree.insert("", "end", values=(when, event.ip, event.reason, event.score))

            for row in self.banned_tree.get_children():
                self.banned_tree.delete(row)
            for ip, until in self.controller.state.ban_store.snapshot().items():
                when = time.strftime("%H:%M:%S", time.localtime(until))
                self.banned_tree.insert("", "end", values=(ip, when))

        def poll_queues(self) -> None:
            while True:
                try:
                    line = self.log_queue.get_nowait()
                except queue.Empty:
                    break
                self.log_text.configure(state="normal")
                self.log_text.insert("end", line + "\n")
                self.log_text.configure(state="disabled")
                self.log_text.see("end")
            if self.event_queue is not None:
                events_changed = False
                while True:
                    try:
                        self.event_queue.get_nowait()
                    except queue.Empty:
                        break
                    events_changed = True
                if events_changed:
                    self.refresh_security_tables()
            self.root.after(200, self.poll_queues)

        def on_close(self) -> None:
            g = GUI_STRINGS[self.lang]
            if self.controller is not None and self.controller.running:
                if not messagebox.askyesno(g["confirm_quit_title"], g["confirm_quit_body"]):
                    return
                self.controller.stop()
            self.root.destroy()

        def run(self) -> None:
            self.root.mainloop()

    LumenDropGUI().run()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="lumendrop", description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("folder", nargs="?", default=str(Path.home() / "LumenDrop"))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--allow-root", action="store_true")
    parser.add_argument("--no-gui", action="store_true")
    parser.add_argument("--no-https", action="store_true")
    return parser.parse_args(argv)


def run_headless(folder: Path, port: int, use_https: bool, logger: logging.Logger) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    pin = generate_pin()
    lan_ip = detect_lan_ip()

    cert_path = key_path = None
    fingerprint = None
    if use_https:
        cert_info = ensure_certificate(app_data_dir() / "tls", lan_ip, logger)
        if cert_info is not None:
            cert_path, key_path, fingerprint = cert_info

    scheme = "https" if cert_path is not None else "http"
    controller = ServerController(
        upload_dir=folder, host="0.0.0.0", port=port, pin=pin, logger=logger,
        cert_path=cert_path, key_path=key_path,
    )
    url = f"{scheme}://{lan_ip}:{port}/"
    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Folder: {folder}")
    print(f"URL:    {url}")
    print(f"PIN:    {pin}")
    if fingerprint is not None:
        print(f"TLS certificate fingerprint (SHA-256): {fingerprint}")
    elif use_https:
        print("HTTPS unavailable this run; serving over plain HTTP. See the log for why.")
    controller.start()
    try:
        while controller.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        controller.stop()


def main() -> None:
    args = parse_args(sys.argv[1:])
    gui_queue: "queue.Queue[str]" = queue.Queue()
    logger = build_logger(gui_queue if not args.no_gui else None)

    if is_elevated_privileges() and not args.allow_root:
        logger.warning(
            "Detected administrator/root privileges. Restart without elevation, "
            "or pass --allow-root if this is intentional."
        )
        if args.no_gui:
            sys.exit(1)

    folder = Path(args.folder).expanduser()

    if args.no_gui:
        run_headless(folder, args.port, not args.no_https, logger)
        return

    build_gui(folder, args.port, args.allow_root, not args.no_https, logger, gui_queue)

if __name__ == "__main__":
    main()
