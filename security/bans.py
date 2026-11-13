from __future__ import annotations

import logging
import threading
import time

from lumendrop.config import SecurityPolicy
from lumendrop.db import Database
from lumendrop.security.detector import SecurityEvent, SecurityEventBus

OFFENSE_FORGIVENESS_SECONDS = 7 * 24 * 3600


class BanStore:
    def __init__(self, db: Database, policy: SecurityPolicy, bus: SecurityEventBus, logger: logging.Logger) -> None:
        self._db = db
        self._policy = policy
        self._bus = bus
        self._logger = logger
        self._lock = threading.Lock()
        self._banned_until: dict[str, float] = {
            client: until
            for client, until in db.query("SELECT client, banned_until FROM bans WHERE banned_until > ?", (time.time(),))
        }

    def is_banned(self, client: str, now: float | None = None) -> float:
        now = time.time() if now is None else now
        with self._lock:
            until = self._banned_until.get(client)
            if until is None:
                return 0.0
            if until <= now:
                del self._banned_until[client]
                return 0.0
            return until - now

    def ban(self, client: str, reason: str) -> float:
        now = time.time()
        row = self._db.one("SELECT offense_count, last_ban FROM bans WHERE client = ?", (client,))
        prior = 0
        if row is not None:
            prior_count, last_ban = row
            prior = int(prior_count) if now - float(last_ban) < OFFENSE_FORGIVENESS_SECONDS else 0
        multipliers = self._policy.ban_escalation
        seconds = self._policy.ban_base_seconds * multipliers[min(prior, len(multipliers) - 1)]
        until = now + seconds
        with self._lock:
            self._banned_until[client] = until
        self._db.execute(
            "INSERT INTO bans (client, banned_until, reason, offense_count, last_ban) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(client) DO UPDATE SET banned_until = excluded.banned_until, reason = excluded.reason, "
            "offense_count = excluded.offense_count, last_ban = excluded.last_ban",
            (client, until, reason[:200], prior + 1, now),
        )
        self._logger.warning("Blocking %s for %ss (offense #%s): %s", client, seconds, prior + 1, reason[:200])
        self._bus.publish(SecurityEvent(now, client, f"blocked:{reason[:120]}", 0.0))
        return until

    def unban(self, client: str) -> None:
        with self._lock:
            self._banned_until.pop(client, None)
        self._db.execute("UPDATE bans SET banned_until = 0 WHERE client = ?", (client,))
        self._logger.info("Block lifted for %s by operator", client)

    def snapshot(self) -> dict[str, float]:
        now = time.time()
        with self._lock:
            return {client: until for client, until in self._banned_until.items() if until > now}


class Reputation:
    def __init__(self, db: Database, cache_seconds: float = 60.0) -> None:
        self._db = db
        self._cache_seconds = cache_seconds
        self._cache: dict[str, tuple[bool, float]] = {}
        self._lock = threading.Lock()

    def _touch(self, client: str, success_delta: int, failure_delta: int) -> None:
        now = time.time()
        self._db.execute(
            "INSERT INTO reputation (client, successes, failures, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(client) DO UPDATE SET successes = successes + excluded.successes, "
            "failures = failures + excluded.failures, last_seen = excluded.last_seen",
            (client, success_delta, failure_delta, now, now),
        )
        with self._lock:
            self._cache.pop(client, None)

    def record_success(self, client: str) -> None:
        self._touch(client, 1, 0)

    def record_failure(self, client: str) -> None:
        self._touch(client, 0, 1)

    def is_trusted(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(client)
            if cached is not None and cached[1] > now:
                return cached[0]
        row = self._db.one("SELECT successes, failures FROM reputation WHERE client = ?", (client,))
        trusted = False
        if row is not None:
            successes, failures = int(row[0]), int(row[1])
            posterior_mean = (successes + 1.0) / (successes + failures + 2.0)
            trusted = successes >= 1 and posterior_mean >= 0.75
        with self._lock:
            if len(self._cache) > 50_000:
                self._cache.clear()
            self._cache[client] = (trusted, now + self._cache_seconds)
        return trusted
