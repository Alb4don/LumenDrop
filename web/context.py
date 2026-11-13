from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from lumendrop.config import Settings, ensure_private_dir
from lumendrop.db import Database
from lumendrop.logging_setup import sanitize_text
from lumendrop.netinfo import HostAllowlist
from lumendrop.security.auth import LoginNonce, PinAuthority, SessionStore
from lumendrop.security.bans import BanStore, Reputation
from lumendrop.security.detector import SecurityEvent, SecurityEventBus, Signal, ThreatDetector
from lumendrop.security.ratelimit import TokenBucketLimiter
from lumendrop.storage.files import FileRepository
from lumendrop.storage.uploads import UploadManager


@dataclass
class AppContext:
    settings: Settings
    logger: logging.Logger
    db: Database
    bus: SecurityEventBus
    detector: ThreatDetector
    bans: BanStore
    reputation: Reputation
    sessions: SessionStore
    pins: PinAuthority
    nonces: LoginNonce
    anon_limiter: TokenBucketLimiter
    auth_limiter: TokenBucketLimiter
    hosts: HostAllowlist
    files: FileRepository
    uploads: UploadManager
    https: bool
    started_at: float = field(default_factory=time.time)

    @property
    def session_cookie(self) -> str:
        return "__Host-lumendrop" if self.https else "lumendrop_session"

    @property
    def nonce_cookie(self) -> str:
        return "__Host-lumendrop_login" if self.https else "lumendrop_login"

    @property
    def lang_cookie(self) -> str:
        return "lumendrop_lang"

    @classmethod
    def build(
        cls,
        settings: Settings,
        share_folder: Path,
        logger: logging.Logger,
        https: bool,
        initial_pin: str | None = None,
        db: Database | None = None,
    ) -> "AppContext":
        data_dir = ensure_private_dir(settings.resolved_data_dir())
        database = db or Database(data_dir / "lumendrop.db")
        policy = settings.policy
        bus = SecurityEventBus()
        reputation = Reputation(database)
        files = FileRepository(share_folder, database, settings.limits, data_dir / "thumbs", logger)
        hosts = HostAllowlist(settings.extra_hostnames)
        ctx = cls(
            settings=settings,
            logger=logger,
            db=database,
            bus=bus,
            detector=ThreatDetector(policy),
            bans=BanStore(database, policy, bus, logger),
            reputation=reputation,
            sessions=SessionStore(policy),
            pins=PinAuthority(database, policy, reputation, logger, initial_pin),
            nonces=LoginNonce(),
            anon_limiter=TokenBucketLimiter(policy.anon_rate_capacity, policy.anon_rate_refill, policy.max_tracked_clients),
            auth_limiter=TokenBucketLimiter(policy.auth_rate_capacity, policy.auth_rate_refill, policy.max_sessions * 2),
            hosts=hosts,
            files=files,
            uploads=UploadManager(share_folder, database, settings.limits, files, logger),
            https=https,
        )
        return ctx

    def report(self, client: str, signals: list[Signal], authenticated: bool, path: str = "") -> bool:
        if not signals:
            return False
        total = sum(s.weight for s in signals)
        names = ",".join(sorted({s.name for s in signals}))
        score = self.detector.accumulate(client, total)
        shift = self.settings.policy.authenticated_prior_shift if authenticated else 0.0
        if self.reputation.is_trusted(client):
            shift += self.settings.policy.trusted_prior_shift
        now = time.time()
        detail = sanitize_text(path)[:200]
        try:
            self.db.execute(
                "INSERT INTO security_events (ts, client, signal, weight, detail) VALUES (?, ?, ?, ?, ?)",
                (now, client, names, total, detail),
            )
        except Exception:
            self.logger.exception("Security event persistence failed")
        self.bus.publish(SecurityEvent(now, client, names, round(total, 2)))
        probability = self.detector.posterior(score, shift)
        self.logger.info("Security signal from %s: %s (weight=%.2f, p=%.3f) %s", client, names, total, probability, detail)
        if self.detector.should_ban(score, shift):
            self.bans.ban(client, f"{names} p={probability:.3f}")
            self.detector.reset(client)
            return True
        return False

    def maintenance(self) -> None:
        try:
            self.uploads.sweep()
            self.sessions.prune()
            self.pins.prune()
            cutoff = time.time() - self.settings.policy.event_retention_days * 86400
            self.db.execute("DELETE FROM security_events WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM bans WHERE banned_until < ? AND last_ban < ?", (time.time(), cutoff))
            self.files.prune_thumbnails()
        except Exception:
            self.logger.exception("Maintenance cycle failed")

    def close(self) -> None:
        self.hosts.stop()
        self.db.close()
