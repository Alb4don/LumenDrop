from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable

from lumendrop.config import SecurityPolicy
from lumendrop.db import Database
from lumendrop.logging_setup import SECRETS
from lumendrop.security.bans import Reputation


def generate_pin(length: int) -> str:
    while True:
        pin = "".join(secrets.choice("0123456789") for _ in range(length))
        if len(set(pin)) >= max(3, length // 2) and not _is_sequential(pin):
            return pin


def _is_sequential(pin: str) -> bool:
    diffs = {(int(b) - int(a)) % 10 for a, b in zip(pin, pin[1:])}
    return len(diffs) == 1


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _agent_fingerprint(user_agent: str) -> str:
    return hashlib.sha256(user_agent[:512].encode("utf-8", "replace")).hexdigest()[:32]


@dataclass
class Session:
    session_id: str
    token_hash: str
    csrf_token: str
    client: str
    agent: str
    created: float
    last_seen: float = field(default=0.0)


class SessionStore:
    def __init__(self, policy: SecurityPolicy) -> None:
        self._policy = policy
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._lock = threading.Lock()

    def create(self, client: str, user_agent: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = time.time()
        session = Session(
            session_id=secrets.token_hex(8),
            token_hash=_hash_token(token),
            csrf_token=secrets.token_urlsafe(32),
            client=client,
            agent=_agent_fingerprint(user_agent),
            created=now,
            last_seen=now,
        )
        with self._lock:
            self._sessions[session.token_hash] = session
            while len(self._sessions) > self._policy.max_sessions:
                self._sessions.popitem(last=False)
        return token, session

    def get(self, token: str | None, user_agent: str, touch: bool = True) -> Session | None:
        if not token or len(token) > 128:
            return None
        token_hash = _hash_token(token)
        now = time.time()
        with self._lock:
            session = self._sessions.get(token_hash)
            if session is None:
                return None
            expired = (
                now - session.created > self._policy.session_absolute_seconds
                or now - session.last_seen > self._policy.session_idle_seconds
            )
            if expired or not hmac.compare_digest(session.agent, _agent_fingerprint(user_agent)):
                if expired:
                    del self._sessions[token_hash]
                return None
            if touch:
                session.last_seen = now
                self._sessions.move_to_end(token_hash)
            return session

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(_hash_token(token), None)

    def revoke_all(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            return count

    def prune(self) -> None:
        now = time.time()
        with self._lock:
            stale = [
                key for key, s in self._sessions.items()
                if now - s.created > self._policy.session_absolute_seconds
                or now - s.last_seen > self._policy.session_idle_seconds
            ]
            for key in stale:
                del self._sessions[key]

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


class LoginNonce:
    def __init__(self, ttl_seconds: int = 900) -> None:
        self._key = secrets.token_bytes(32)
        self._ttl = ttl_seconds

    def issue(self) -> str:
        issued = int(time.time()).to_bytes(8, "big")
        nonce = secrets.token_bytes(16)
        mac = hmac.new(self._key, issued + nonce, hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(issued + nonce + mac).decode("ascii").rstrip("=")

    def verify(self, form_value: str | None, cookie_value: str | None) -> bool:
        if not form_value or not cookie_value or len(form_value) > 128:
            return False
        if not hmac.compare_digest(form_value, cookie_value):
            return False
        try:
            raw = base64.urlsafe_b64decode(form_value + "=" * (-len(form_value) % 4))
        except (ValueError, TypeError):
            return False
        if len(raw) != 40:
            return False
        issued, nonce, mac = raw[:8], raw[8:24], raw[24:]
        expected = hmac.new(self._key, issued + nonce, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(mac, expected):
            return False
        age = time.time() - int.from_bytes(issued, "big")
        return -60 <= age <= self._ttl


@dataclass(frozen=True)
class LoginDecision:
    ok: bool
    reason: str
    retry_after: int = 0


class PinAuthority:
    def __init__(
        self,
        db: Database,
        policy: SecurityPolicy,
        reputation: Reputation,
        logger: logging.Logger,
        initial_pin: str | None = None,
    ) -> None:
        self._db = db
        self._policy = policy
        self._reputation = reputation
        self._logger = logger
        self._lock = threading.Lock()
        self._pin = initial_pin or generate_pin(policy.pin_length)
        SECRETS.add(self._pin)
        self._global_failures: deque[float] = deque()
        self._paused_until = 0.0
        self._listeners: list[Callable[[str, str], None]] = []

    @property
    def pin(self) -> str:
        with self._lock:
            return self._pin

    def on_rotate(self, listener: Callable[[str, str], None]) -> None:
        self._listeners.append(listener)

    def rotate(self, reason: str) -> str:
        new_pin = generate_pin(self._policy.pin_length)
        with self._lock:
            self._pin = new_pin
            self._global_failures.clear()
        SECRETS.add(new_pin)
        self._logger.warning("Access PIN rotated (%s)", reason)
        for listener in list(self._listeners):
            try:
                listener(new_pin, reason)
            except Exception:
                self._logger.exception("PIN rotation listener failed")
        return new_pin

    def _client_lock_remaining(self, client: str, now: float) -> int:
        window = self._policy.login_window_seconds
        rows = self._db.query(
            "SELECT ts FROM login_failures WHERE client = ? AND ts > ? ORDER BY ts DESC LIMIT ?",
            (client, now - window, self._policy.login_attempts_per_window),
        )
        if len(rows) < self._policy.login_attempts_per_window:
            return 0
        oldest_relevant = rows[-1][0]
        return max(0, int(window - (now - oldest_relevant)) + 1)

    def precheck(self, client: str) -> LoginDecision:
        now = time.time()
        remaining = self._client_lock_remaining(client, now)
        if remaining > 0:
            return LoginDecision(False, "locked", remaining)
        with self._lock:
            paused = self._paused_until - now
        if paused > 0 and not self._reputation.is_trusted(client):
            return LoginDecision(False, "paused", int(paused) + 1)
        return LoginDecision(True, "ok")

    def verify(self, client: str, candidate: str) -> LoginDecision:
        decision = self.precheck(client)
        if not decision.ok:
            return decision
        digits = "".join(ch for ch in (candidate or "")[:64] if ch.isdigit() and ch.isascii())
        with self._lock:
            expected = self._pin
        matched = hmac.compare_digest(digits.encode(), expected.encode()) and len(digits) == len(expected)
        if matched:
            self._db.execute("DELETE FROM login_failures WHERE client = ?", (client,))
            self._reputation.record_success(client)
            return LoginDecision(True, "ok")
        self._register_failure(client)
        return LoginDecision(False, "bad_pin")

    def _register_failure(self, client: str) -> None:
        now = time.time()
        self._db.execute("INSERT INTO login_failures (client, ts) VALUES (?, ?)", (client, now))
        self._reputation.record_failure(client)
        window = self._policy.login_window_seconds
        rotate = False
        with self._lock:
            self._global_failures.append(now)
            while self._global_failures and now - self._global_failures[0] > window:
                self._global_failures.popleft()
            if len(self._global_failures) >= self._policy.global_login_failure_budget:
                rotate = True
                self._paused_until = now + max(60, window // 3)
        if rotate:
            self.rotate("distributed_bruteforce")

    def prune(self) -> None:
        cutoff = time.time() - max(self._policy.login_window_seconds * 4, 86400)
        self._db.execute("DELETE FROM login_failures WHERE ts < ?", (cutoff,))
