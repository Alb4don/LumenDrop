from __future__ import annotations

import hashlib
import logging
import os
import stat as stat_module
import threading
import time
import warnings
from dataclasses import dataclass
from pathlib import Path

from lumendrop.config import Limits, ensure_private_dir
from lumendrop.db import Database
from lumendrop.paths import resolve_shared_file
from lumendrop.security.filescan import (
    RASTER_IMAGE_EXTENSIONS,
    RASTER_IMAGE_KINDS,
    FileVerdict,
    classify_file,
)

try:
    from PIL import Image, ImageOps

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

_PIL_FORMATS = ["JPEG", "PNG", "GIF", "WEBP", "BMP"]
SORT_KEYS = {"newest", "oldest", "name", "size"}


@dataclass(frozen=True)
class FileEntry:
    name: str
    size: int
    mtime: float
    mtime_ns: int
    kind: str
    quarantined: bool
    reasons: tuple[str, ...]
    sha256: str | None

    @property
    def is_raster_image(self) -> bool:
        ext = os.path.splitext(self.name)[1].lower()
        return ext in RASTER_IMAGE_EXTENSIONS and self.kind in RASTER_IMAGE_KINDS

    def to_public(self, thumbs_enabled: bool, thumb_max_bytes: int) -> dict:
        image = self.is_raster_image
        return {
            "name": self.name,
            "size": self.size,
            "mtime": int(self.mtime),
            "image": image,
            "thumb": image and thumbs_enabled and self.size <= thumb_max_bytes,
            "quarantined": self.quarantined,
            "reasons": list(self.reasons),
            "sha256": self.sha256,
        }


class FileRepository:
    def __init__(self, folder: Path, db: Database, limits: Limits, thumb_dir: Path, logger: logging.Logger) -> None:
        self.folder = folder.resolve()
        self.folder_key = os.path.normcase(str(self.folder))
        self.db = db
        self.limits = limits
        self.logger = logger
        self.thumb_dir = ensure_private_dir(thumb_dir)
        self.thumbs_enabled = PIL_AVAILABLE
        self._thumb_slots = threading.BoundedSemaphore(max(1, limits.thumb_workers))
        self._thumb_locks: dict[str, threading.Lock] = {}
        self._thumb_locks_guard = threading.Lock()
        self._scan_lock = threading.Lock()

    def resolve(self, name: str) -> Path | None:
        return resolve_shared_file(self.folder, name)

    def _load_meta(self) -> dict[str, tuple]:
        rows = self.db.query(
            "SELECT name, size, mtime_ns, sha256, kind, quarantined, reasons FROM file_meta WHERE folder = ?",
            (self.folder_key,),
        )
        return {row[0]: row[1:] for row in rows}

    def scan(self) -> list[FileEntry]:
        with self._scan_lock:
            meta = self._load_meta()
            entries: list[FileEntry] = []
            upserts: list[tuple] = []
            seen: set[str] = set()
            try:
                iterator = os.scandir(self.folder)
            except OSError:
                self.logger.error("Shared folder is not readable")
                return []
            with iterator:
                for item in iterator:
                    name = item.name
                    if name.startswith("."):
                        continue
                    try:
                        if not item.is_file(follow_symlinks=False):
                            continue
                        st = item.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat_module.S_ISREG(st.st_mode):
                        continue
                    seen.add(name)
                    cached = meta.get(name)
                    if cached is not None and cached[0] == st.st_size and cached[1] == st.st_mtime_ns:
                        _, _, sha, kind, quarantined, reasons = cached
                        verdict = FileVerdict(kind, bool(quarantined), 0, tuple(r for r in reasons.split(",") if r))
                    else:
                        verdict = classify_file(Path(item.path))
                        sha = None
                        upserts.append((
                            self.folder_key, name, st.st_size, st.st_mtime_ns, None, verdict.kind,
                            int(verdict.quarantined), ",".join(verdict.reasons), None,
                        ))
                    entries.append(FileEntry(
                        name=name, size=st.st_size, mtime=st.st_mtime, mtime_ns=st.st_mtime_ns, kind=verdict.kind,
                        quarantined=verdict.quarantined, reasons=verdict.reasons, sha256=sha,
                    ))
            stale = [name for name in meta if name not in seen]
            if upserts or stale:
                try:
                    with self.db.transaction() as conn:
                        if upserts:
                            conn.executemany(
                                "INSERT INTO file_meta (folder, name, size, mtime_ns, sha256, kind, quarantined, "
                                "reasons, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                                "ON CONFLICT(folder, name) DO UPDATE SET size = excluded.size, "
                                "mtime_ns = excluded.mtime_ns, sha256 = excluded.sha256, kind = excluded.kind, "
                                "quarantined = excluded.quarantined, reasons = excluded.reasons",
                                upserts,
                            )
                        if stale:
                            conn.executemany(
                                "DELETE FROM file_meta WHERE folder = ? AND name = ?",
                                [(self.folder_key, name) for name in stale],
                            )
                except Exception:
                    self.logger.exception("Metadata cache update failed")
            return entries

    def list(self, query: str, sort: str, offset: int, limit: int) -> tuple[list[FileEntry], int]:
        entries = self.scan()
        if query:
            needle = query.casefold()
            entries = [e for e in entries if needle in e.name.casefold()]
        if sort == "oldest":
            entries.sort(key=lambda e: (e.mtime_ns, e.name))
        elif sort == "name":
            entries.sort(key=lambda e: e.name.casefold())
        elif sort == "size":
            entries.sort(key=lambda e: (-e.size, e.name))
        else:
            entries.sort(key=lambda e: (-e.mtime_ns, e.name))
        total = len(entries)
        return entries[offset:offset + limit], total

    def entry(self, name: str) -> FileEntry | None:
        path = self.resolve(name)
        if path is None:
            return None
        st = path.stat()
        row = self.db.one(
            "SELECT size, mtime_ns, sha256, kind, quarantined, reasons FROM file_meta WHERE folder = ? AND name = ?",
            (self.folder_key, path.name),
        )
        if row is not None and row[0] == st.st_size and row[1] == st.st_mtime_ns:
            return FileEntry(path.name, st.st_size, st.st_mtime, st.st_mtime_ns, row[3], bool(row[4]),
                             tuple(r for r in row[5].split(",") if r), row[2])
        verdict = classify_file(path)
        return FileEntry(path.name, st.st_size, st.st_mtime, st.st_mtime_ns, verdict.kind, verdict.quarantined,
                         verdict.reasons, None)

    def record_upload(self, path: Path, sha256: str, verdict: FileVerdict) -> None:
        st = path.stat()
        self.db.execute(
            "INSERT INTO file_meta (folder, name, size, mtime_ns, sha256, kind, quarantined, reasons, uploaded_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(folder, name) DO UPDATE SET size = excluded.size, "
            "mtime_ns = excluded.mtime_ns, sha256 = excluded.sha256, kind = excluded.kind, "
            "quarantined = excluded.quarantined, reasons = excluded.reasons, uploaded_at = excluded.uploaded_at",
            (self.folder_key, path.name, st.st_size, st.st_mtime_ns, sha256, verdict.kind, int(verdict.quarantined),
             ",".join(verdict.reasons), time.time()),
        )

    def delete(self, name: str) -> bool:
        path = self.resolve(name)
        if path is None:
            return False
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        self.db.execute("DELETE FROM file_meta WHERE folder = ? AND name = ?", (self.folder_key, path.name))
        return True

    def _thumb_lock(self, key: str) -> threading.Lock:
        with self._thumb_locks_guard:
            lock = self._thumb_locks.get(key)
            if lock is None:
                if len(self._thumb_locks) > 4096:
                    self._thumb_locks.clear()
                lock = threading.Lock()
                self._thumb_locks[key] = lock
            return lock

    def thumbnail(self, name: str) -> Path | None:
        if not self.thumbs_enabled:
            return None
        entry = self.entry(name)
        if entry is None or not entry.is_raster_image or entry.size > self.limits.thumb_max_source_bytes:
            return None
        source = self.folder / entry.name
        key = hashlib.sha256(f"{self.folder_key}|{entry.name}|{entry.size}|{entry.mtime_ns}".encode()).hexdigest()
        target = self.thumb_dir / f"{key}.jpg"
        if target.exists():
            return target
        with self._thumb_lock(key):
            if target.exists():
                return target
            with self._thumb_slots:
                return self._render_thumbnail(source, target)

    def _render_thumbnail(self, source: Path, target: Path) -> Path | None:
        size = self.limits.thumb_size
        Image.MAX_IMAGE_PIXELS = self.limits.thumb_max_pixels
        tmp = target.with_name(f".{target.name}.{threading.get_ident()}.tmp")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(source, formats=_PIL_FORMATS) as img:
                    if img.width * img.height > self.limits.thumb_max_pixels:
                        return None
                    if img.format == "JPEG":
                        img.draft("RGB", (size * 2, size * 2))
                    img.seek(0)
                    frame = ImageOps.exif_transpose(img)
                    frame.thumbnail((size, size), Image.Resampling.LANCZOS)
                    if frame.mode not in ("RGB", "L"):
                        background = Image.new("RGB", frame.size, (10, 17, 26))
                        rgba = frame.convert("RGBA")
                        background.paste(rgba, mask=rgba.split()[-1])
                        frame = background
                    frame.save(tmp, "JPEG", quality=78, optimize=True, progressive=True)
            os.replace(tmp, target)
            return target
        except Exception:
            self.logger.info("Thumbnail skipped for an unreadable image")
            try:
                tmp.unlink()
            except OSError:
                pass
            return None

    def prune_thumbnails(self, keep: int = 4000) -> None:
        try:
            items = sorted(self.thumb_dir.glob("*.jpg"), key=lambda p: p.stat().st_mtime)
        except OSError:
            return
        for path in items[:-keep] if len(items) > keep else []:
            try:
                path.unlink()
            except OSError:
                pass
