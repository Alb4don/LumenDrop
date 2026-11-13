from __future__ import annotations

import errno
import hashlib
import hmac
import logging
import os
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import AsyncIterator

import anyio

from lumendrop.config import Limits
from lumendrop.db import Database
from lumendrop.paths import STAGING_DIR_NAME, disk_free_bytes, reserve_unique_path, safe_filename
from lumendrop.security.filescan import classify_bytes
from lumendrop.storage.files import FileRepository

_UPLOAD_ID = re.compile(r"[A-Za-z0-9_-]{32}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
STUCK_FINALIZE_SECONDS = 3600
ORPHAN_GRACE_SECONDS = 3600


def sha256_stream(handle, block: int = 4 * 1024 * 1024) -> str:
    if hasattr(hashlib, "file_digest"):
        return hashlib.file_digest(handle, "sha256").hexdigest()
    digest = hashlib.sha256()
    for piece in iter(lambda: handle.read(block), b""):
        digest.update(piece)
    return digest.hexdigest()


class UploadError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def is_valid_upload_id(value: str) -> bool:
    return bool(value) and bool(_UPLOAD_ID.fullmatch(value))


def choose_chunk_size(total_size: int, hint: int | None, limits: Limits) -> int:
    floor = -(-total_size // 4000)
    if hint is None or hint <= 0:
        target = max(limits.default_chunk, floor)
    else:
        target = max(hint, floor)
    target = max(limits.min_chunk, min(limits.max_chunk, target))
    align = 64 * 1024
    return max(limits.min_chunk, (target // align) * align)


class UploadManager:
    def __init__(self, folder: Path, db: Database, limits: Limits, files: FileRepository, logger: logging.Logger) -> None:
        self.folder = folder.resolve()
        self.folder_key = os.path.normcase(str(self.folder))
        self.db = db
        self.limits = limits
        self.files = files
        self.logger = logger
        self.staging = self.folder / STAGING_DIR_NAME
        self.staging.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            self._hide_windows(self.staging)

    @staticmethod
    def _hide_windows(path: Path) -> None:
        try:
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02)
        except Exception:
            pass

    def _staging_path(self, upload_id: str) -> Path:
        return self.staging / f"{upload_id}.part"

    def _row(self, upload_id: str) -> dict | None:
        if not is_valid_upload_id(upload_id):
            return None
        row = self.db.one(
            "SELECT id, owner, filename, total_size, chunk_size, total_chunks, received_count, status, created, updated "
            "FROM uploads WHERE id = ? AND folder = ?",
            (upload_id, self.folder_key),
        )
        if row is None:
            return None
        keys = ("id", "owner", "filename", "total_size", "chunk_size", "total_chunks", "received_count", "status",
                "created", "updated")
        data = dict(zip(keys, row))
        if time.time() - data["updated"] > self.limits.upload_session_ttl:
            self._discard(upload_id)
            return None
        return data

    def _received(self, upload_id: str) -> list[int]:
        return [r[0] for r in self.db.query("SELECT idx FROM upload_chunks WHERE upload_id = ? ORDER BY idx", (upload_id,))]

    def _pending_bytes(self) -> int:
        row = self.db.one(
            "SELECT COALESCE(SUM(MAX(total_size - received_count * chunk_size, 0)), 0) FROM uploads "
            "WHERE folder = ? AND status = 'open'",
            (self.folder_key,),
        )
        return int(row[0]) if row else 0

    def create(self, owner: str, raw_filename: str, total_size: int, chunk_hint: int | None) -> dict:
        if total_size <= 0 or total_size > self.limits.max_upload_bytes:
            raise UploadError("file_too_large", 413)
        filename = safe_filename(raw_filename, self.limits.max_filename_length)
        per_owner = self.db.one(
            "SELECT COUNT(*) FROM uploads WHERE owner = ? AND status = 'open'", (owner,),
        )[0]
        overall = self.db.one("SELECT COUNT(*) FROM uploads WHERE status = 'open'")[0]
        if per_owner >= self.limits.max_uploads_per_session or overall >= self.limits.max_uploads_total:
            raise UploadError("too_many_uploads", 429)
        free = disk_free_bytes(self.folder)
        if free - self._pending_bytes() - self.limits.disk_reserve_bytes < total_size:
            raise UploadError("insufficient_storage", 507)
        chunk_size = choose_chunk_size(total_size, chunk_hint, self.limits)
        total_chunks = max(1, -(-total_size // chunk_size))
        upload_id = secrets.token_urlsafe(24)
        staging = self._staging_path(upload_id)
        try:
            self.staging.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise UploadError("insufficient_storage", 507) from exc
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(staging, flags, 0o600)
            try:
                os.ftruncate(fd, total_size)
            finally:
                os.close(fd)
        except OSError as exc:
            try:
                staging.unlink()
            except OSError:
                pass
            if exc.errno in (errno.EFBIG, errno.EINVAL):
                raise UploadError("file_too_large", 413) from exc
            if exc.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)):
                raise UploadError("insufficient_storage", 507) from exc
            raise
        now = time.time()
        self.db.execute(
            "INSERT INTO uploads (id, folder, owner, filename, total_size, chunk_size, total_chunks, received_count, "
            "status, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'open', ?, ?)",
            (upload_id, self.folder_key, owner, filename, total_size, chunk_size, total_chunks, now, now),
        )
        return {
            "upload_id": upload_id,
            "filename": filename,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "received": [],
        }

    def status(self, upload_id: str) -> dict:
        row = self._row(upload_id)
        if row is None:
            raise UploadError("not_found", 404)
        return {
            "upload_id": row["id"],
            "filename": row["filename"],
            "total_size": row["total_size"],
            "chunk_size": row["chunk_size"],
            "total_chunks": row["total_chunks"],
            "received": self._received(upload_id),
            "status": row["status"],
        }

    @staticmethod
    def expected_length(row: dict, index: int) -> int:
        if index < row["total_chunks"] - 1:
            return row["chunk_size"]
        return row["total_size"] - row["chunk_size"] * (row["total_chunks"] - 1)

    async def write_chunk(
        self,
        upload_id: str,
        index: int,
        body: AsyncIterator[bytes],
        declared_length: int | None,
        checksum: str | None,
    ) -> dict:
        row = await anyio.to_thread.run_sync(self._row, upload_id)
        if row is None:
            raise UploadError("not_found", 404)
        if row["status"] != "open":
            raise UploadError("conflict", 409)
        if index < 0 or index >= row["total_chunks"]:
            raise UploadError("invalid_request", 400)
        expected = self.expected_length(row, index)
        if declared_length is not None and declared_length != expected:
            raise UploadError("invalid_request", 400)
        if checksum is not None:
            checksum = checksum.strip().lower()
            if not _SHA256_HEX.fullmatch(checksum):
                raise UploadError("invalid_request", 400)
        hasher = hashlib.sha256() if checksum else None
        staging = self._staging_path(upload_id)
        offset = index * row["chunk_size"]
        received = 0
        buffer = bytearray()
        block = self.limits.io_block

        def _open():
            handle = open(staging, "r+b")
            handle.seek(offset)
            return handle

        try:
            handle = await anyio.to_thread.run_sync(_open)
        except FileNotFoundError as exc:
            raise UploadError("not_found", 404) from exc
        try:
            async for piece in body:
                if not piece:
                    continue
                received += len(piece)
                if received > expected:
                    raise UploadError("file_too_large", 413)
                buffer += piece
                if len(buffer) >= block:
                    data = bytes(buffer)
                    buffer.clear()
                    if hasher is not None:
                        hasher.update(data)
                    await anyio.to_thread.run_sync(handle.write, data)
            if buffer:
                data = bytes(buffer)
                buffer.clear()
                if hasher is not None:
                    hasher.update(data)
                await anyio.to_thread.run_sync(handle.write, data)
        finally:
            await anyio.to_thread.run_sync(handle.close)
        if received != expected:
            raise UploadError("invalid_request", 400)
        if hasher is not None and not hmac.compare_digest(hasher.hexdigest(), checksum):
            raise UploadError("checksum_mismatch", 422)
        return await anyio.to_thread.run_sync(self._mark_received, upload_id, index)

    def _mark_received(self, upload_id: str, index: int) -> dict:
        now = time.time()
        with self.db.transaction() as conn:
            exists = conn.execute(
                "SELECT 1 FROM uploads WHERE id = ? AND status = 'open'", (upload_id,),
            ).fetchone()
            if exists is None:
                raise UploadError("not_found", 404)
            inserted = conn.execute(
                "INSERT OR IGNORE INTO upload_chunks (upload_id, idx) VALUES (?, ?)", (upload_id, index),
            ).rowcount
            if inserted:
                conn.execute(
                    "UPDATE uploads SET received_count = received_count + 1, updated = ? WHERE id = ?",
                    (now, upload_id),
                )
            else:
                conn.execute("UPDATE uploads SET updated = ? WHERE id = ?", (now, upload_id))
            row = conn.execute("SELECT received_count, total_chunks FROM uploads WHERE id = ?", (upload_id,)).fetchone()
        if row is None:
            raise UploadError("not_found", 404)
        return {"received_count": row[0], "total_chunks": row[1], "complete": row[0] >= row[1]}

    def finalize(self, upload_id: str) -> dict:
        row = self._row(upload_id)
        if row is None:
            raise UploadError("not_found", 404)
        claimed = self.db.execute(
            "UPDATE uploads SET status = 'finalizing', updated = ? WHERE id = ? AND status = 'open' "
            "AND received_count = total_chunks",
            (time.time(), upload_id),
        )
        if claimed != 1:
            raise UploadError("conflict", 409)
        staging = self._staging_path(upload_id)
        reserved: Path | None = None
        try:
            st = os.stat(staging)
            if st.st_size != row["total_size"]:
                self._discard(upload_id)
                raise UploadError("invalid_request", 400)
            with open(staging, "rb") as handle:
                digest = sha256_stream(handle)
                handle.seek(0)
                header = handle.read(4096)
            verdict = classify_bytes(row["filename"], header)
            reserved = reserve_unique_path(self.folder, row["filename"])
            self._replace_with_retry(staging, reserved)
            final = reserved
            if os.name == "posix":
                try:
                    os.chmod(final, 0o644)
                except OSError:
                    pass
            reserved = None
            self.files.record_upload(final, digest, verdict)
            self.db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
            return {
                "name": final.name,
                "size": row["total_size"],
                "sha256": digest,
                "quarantined": verdict.quarantined,
                "reasons": list(verdict.reasons),
                "kind": verdict.kind,
            }
        except UploadError:
            raise
        except Exception:
            self.db.execute("UPDATE uploads SET status = 'open' WHERE id = ? AND status = 'finalizing'", (upload_id,))
            raise
        finally:
            if reserved is not None:
                try:
                    reserved.unlink()
                except OSError:
                    pass

    @staticmethod
    def _replace_with_retry(source: Path, target: Path) -> None:
        delay = 0.05
        for attempt in range(8):
            try:
                os.replace(source, target)
                return
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 1.0)

    def _discard(self, upload_id: str) -> None:
        self.db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
        try:
            self._staging_path(upload_id).unlink()
        except OSError:
            pass

    def cancel(self, upload_id: str) -> bool:
        row = self._row(upload_id)
        if row is None or row["status"] != "open":
            return False
        self._discard(upload_id)
        return True

    def active_count(self) -> int:
        row = self.db.one("SELECT COUNT(*) FROM uploads WHERE folder = ? AND status = 'open'", (self.folder_key,))
        return int(row[0]) if row else 0

    def sweep(self) -> None:
        now = time.time()
        expired = self.db.query(
            "SELECT id FROM uploads WHERE folder = ? AND (updated < ? OR (status = 'finalizing' AND updated < ?))",
            (self.folder_key, now - self.limits.upload_session_ttl, now - STUCK_FINALIZE_SECONDS),
        )
        for (upload_id,) in expired:
            self._discard(upload_id)
        known = {r[0] for r in self.db.query("SELECT id FROM uploads WHERE folder = ?", (self.folder_key,))}
        try:
            entries = list(os.scandir(self.staging))
        except OSError:
            return
        for entry in entries:
            name = entry.name
            upload_id = name[:-5] if name.endswith(".part") else None
            if upload_id in known:
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if now - entry.stat(follow_symlinks=False).st_mtime > ORPHAN_GRACE_SECONDS:
                        shutil.rmtree(entry.path, ignore_errors=True)
                    continue
                if now - entry.stat(follow_symlinks=False).st_mtime > ORPHAN_GRACE_SECONDS:
                    os.unlink(entry.path)
            except OSError:
                continue
