from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import re
import sys
import threading
from pathlib import Path

from lumendrop.config import ensure_private_dir

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_\-])")


def _redact_token(match: "re.Match[str]") -> str:
    candidate = match.group(0)
    has_upper = any(c.isupper() for c in candidate)
    has_lower = any(c.islower() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    if has_upper and has_lower and has_digit:
        return "[REDACTED-TOKEN]"
    return candidate
_COOKIE_PATTERN = re.compile(r"((?:session|cookie|token|csrf)[\w\-]*\s*[=:]\s*)[^;&\s,]+", re.IGNORECASE)
MAX_MESSAGE_CHARS = 4000


class SecretRegistry:
    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def add(self, value: str) -> None:
        if value and len(value) >= 4:
            with self._lock:
                self._secrets.add(value)

    def discard(self, value: str) -> None:
        with self._lock:
            self._secrets.discard(value)

    def scrub(self, text: str) -> str:
        with self._lock:
            secrets_snapshot = sorted(self._secrets, key=len, reverse=True)
        for secret in secrets_snapshot:
            if secret in text:
                text = text.replace(secret, "[REDACTED]")
        return text


SECRETS = SecretRegistry()


def sanitize_text(text: str, single_line: bool = True) -> str:
    text = SECRETS.scrub(text)
    text = _COOKIE_PATTERN.sub(r"\1[REDACTED]", text)
    text = _TOKEN_PATTERN.sub(_redact_token, text)
    if single_line:
        text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", " ")
    text = _CONTROL_CHARS.sub("\ufffd", text)
    if len(text) > MAX_MESSAGE_CHARS:
        text = text[:MAX_MESSAGE_CHARS] + "\u2026"
    return text


def safe_repr(value: object, limit: int = 120) -> str:
    text = sanitize_text(str(value))
    return text if len(text) <= limit else text[:limit] + "\u2026"


class RedactingFormatter(logging.Formatter):
    def __init__(self, fmt: str, datefmt: str, include_traceback: bool) -> None:
        super().__init__(fmt, datefmt)
        self.include_traceback = include_traceback

    def format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        clone = logging.makeLogRecord(record.__dict__)
        clone.msg = sanitize_text(message)
        clone.args = ()
        clone.exc_text = None
        clone.stack_info = None
        if not self.include_traceback:
            clone.exc_info = None
        base = super().format(clone)
        if self.include_traceback and record.exc_info:
            lines = base.split("\n")
            return "\n".join([lines[0]] + [sanitize_text(line, single_line=False) for line in lines[1:]])
        return base


class BoundedQueueHandler(logging.Handler):
    def __init__(self, sink: "queue.Queue[str]") -> None:
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.put_nowait(self.format(record))
        except queue.Full:
            pass
        except Exception:
            self.handleError(record)


def _restrict_file(path: Path) -> None:
    if os.name == "posix" and path.exists():
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def build_logger(
    data_dir: Path,
    gui_queue: "queue.Queue[str] | None" = None,
    level: int = logging.INFO,
    console: bool = True,
) -> logging.Logger:
    logger = logging.getLogger("lumendrop")
    logger.setLevel(level)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    log_dir = ensure_private_dir(data_dir / "logs")
    log_path = log_dir / "lumendrop.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=5_000_000, backupCount=5, encoding="utf-8", delay=False,
    )
    file_handler.setFormatter(RedactingFormatter(fmt, datefmt, include_traceback=True))
    logger.addHandler(file_handler)
    _restrict_file(log_path)

    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(RedactingFormatter(fmt, datefmt, include_traceback=False))
        logger.addHandler(console_handler)

    if gui_queue is not None:
        gui_handler = BoundedQueueHandler(gui_queue)
        gui_handler.setFormatter(RedactingFormatter(fmt, datefmt, include_traceback=False))
        logger.addHandler(gui_handler)

    logger.propagate = False
    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi", "asyncio"):
        external = logging.getLogger(name)
        external.handlers = [file_handler]
        external.setLevel(logging.WARNING)
        external.propagate = False
    for name in ("uvicorn.access", "multipart", "python_multipart"):
        external = logging.getLogger(name)
        external.handlers = [logging.NullHandler()]
        external.propagate = False
    return logger
