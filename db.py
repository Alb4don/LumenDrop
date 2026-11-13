from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            client TEXT NOT NULL,
            signal TEXT NOT NULL,
            weight REAL NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_client_ts ON security_events(client, ts);

        CREATE TABLE IF NOT EXISTS bans (
            client TEXT PRIMARY KEY,
            banned_until REAL NOT NULL,
            reason TEXT NOT NULL,
            offense_count INTEGER NOT NULL,
            last_ban REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reputation (
            client TEXT PRIMARY KEY,
            successes INTEGER NOT NULL DEFAULT 0,
            failures INTEGER NOT NULL DEFAULT 0,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client TEXT NOT NULL,
            ts REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_failures_client_ts ON login_failures(client, ts);
        CREATE INDEX IF NOT EXISTS idx_login_failures_ts ON login_failures(ts);

        CREATE TABLE IF NOT EXISTS uploads (
            id TEXT PRIMARY KEY,
            folder TEXT NOT NULL,
            owner TEXT NOT NULL,
            filename TEXT NOT NULL,
            total_size INTEGER NOT NULL,
            chunk_size INTEGER NOT NULL,
            total_chunks INTEGER NOT NULL,
            received_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            created REAL NOT NULL,
            updated REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_uploads_owner ON uploads(owner, status);
        CREATE INDEX IF NOT EXISTS idx_uploads_updated ON uploads(updated);

        CREATE TABLE IF NOT EXISTS upload_chunks (
            upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
            idx INTEGER NOT NULL,
            PRIMARY KEY (upload_id, idx)
        ) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS file_meta (
            folder TEXT NOT NULL,
            name TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            sha256 TEXT,
            kind TEXT NOT NULL DEFAULT '',
            quarantined INTEGER NOT NULL DEFAULT 0,
            reasons TEXT NOT NULL DEFAULT '',
            uploaded_at REAL,
            PRIMARY KEY (folder, name)
        ) WITHOUT ROWID;
        """,
    ),
]


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, isolation_level=None, timeout=10.0,
        )
        self._closed = False
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.execute("PRAGMA trusted_schema=OFF")
        self._migrate()
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        if os.name != "posix":
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                try:
                    os.chmod(candidate, 0o600)
                except OSError:
                    pass

    def _migrate(self) -> None:
        with self._lock:
            current = self._conn.execute("PRAGMA user_version").fetchone()[0]
            for version, script in MIGRATIONS:
                if version <= current:
                    continue
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in [s.strip() for s in script.split(";") if s.strip()]:
                        self._conn.execute(statement)
                    self._conn.execute(f"PRAGMA user_version = {int(version)}")
                    self._conn.execute("COMMIT")
                except Exception:
                    self._conn.execute("ROLLBACK")
                    raise

    @property
    def closed(self) -> bool:
        return self._closed

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self._lock:
            if self._closed:
                return 0
            cursor = self._conn.execute(sql, params)
            return cursor.rowcount

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]:
        with self._lock:
            if self._closed:
                return []
            return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] = ()) -> tuple | None:
        with self._lock:
            if self._closed:
                return None
            return self._conn.execute(sql, params).fetchone()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("database_closed")
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._conn.execute("PRAGMA optimize")
            except sqlite3.Error:
                pass
            self._conn.close()
