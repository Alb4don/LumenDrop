from __future__ import annotations

import errno
import os
import stat
import sys
import tempfile
import unicodedata
from pathlib import Path

STAGING_DIR_NAME = ".lumendrop_staging"

_WINDOWS_FORBIDDEN = set('<>:"/\\|?*')
_ALLOWED_PUNCT = set(" ._-()[]{}+,@&'#!~=%$^;")
_RESERVED_STEMS = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{suffix}" for prefix in ("COM", "LPT") for suffix in list("123456789") + ["¹", "²", "³"]
}
MAX_NAME_BYTES = 240


class FolderRejected(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _allowed_char(ch: str) -> bool:
    if ch in _WINDOWS_FORBIDDEN:
        return False
    if ch in _ALLOWED_PUNCT:
        return True
    category = unicodedata.category(ch)
    return category[0] in ("L", "N", "M")


def _truncate_utf8(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def safe_filename(raw_name: str, max_chars: int = 200) -> str:
    raw_name = (raw_name or "").replace("\x00", "")
    raw_name = raw_name.replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", raw_name)
    cleaned = "".join(ch if _allowed_char(ch) else "_" for ch in name)
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    cleaned = cleaned.strip().strip(".").strip()
    if not cleaned or set(cleaned) <= {"_", " ", "."}:
        cleaned = "file"
    stem, dot, suffix = cleaned.rpartition(".")
    if not dot:
        stem, suffix = cleaned, ""
    suffix = suffix[:24]
    if stem.split(".")[0].upper().rstrip(" ") in _RESERVED_STEMS:
        stem = "_" + stem
    budget_chars = max(1, max_chars - (len(suffix) + 1 if suffix else 0))
    stem = stem[:budget_chars].rstrip(" .") or "file"
    suffix_part = f".{suffix}" if suffix else ""
    stem = _truncate_utf8(stem, MAX_NAME_BYTES - len(suffix_part.encode("utf-8"))).rstrip(" .") or "file"
    return f"{stem}{suffix_part}"


def is_acceptable_existing_name(name: str) -> bool:
    if not name or len(name) > 255:
        return False
    if name in (".", "..") or name.startswith("."):
        return False
    if "/" in name or "\\" in name or "\x00" in name:
        return False
    for ch in name:
        category = unicodedata.category(ch)
        if category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            return False
    if sys.platform == "win32" and (":" in name or name.rstrip(" .") != name):
        return False
    return True


def resolve_shared_file(folder: Path, name: str) -> Path | None:
    if not is_acceptable_existing_name(name):
        return None
    folder_resolved = folder.resolve()
    candidate = folder_resolved / name
    try:
        st = os.lstat(candidate)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        real = candidate.resolve(strict=True)
    except OSError:
        return None
    if real.parent != folder_resolved:
        return None
    return real


def reserve_unique_path(folder: Path, filename: str) -> Path:
    stem, dot, suffix = filename.rpartition(".")
    if not dot or not stem:
        stem, suffix_part = filename, ""
    else:
        suffix_part = f".{suffix}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    for counter in range(0, 10_000):
        candidate_name = filename if counter == 0 else f"{stem} ({counter}){suffix_part}"
        candidate = folder / candidate_name
        try:
            fd = os.open(candidate, flags, 0o644)
        except FileExistsError:
            continue
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                continue
            raise
        os.close(fd)
        return candidate
    raise FileExistsError("no_unique_name")


def _norm(path: Path) -> str:
    text = os.path.normcase(str(path))
    return text.rstrip("\\/") or text


def _is_within(child: Path, parent: Path) -> bool:
    child_n, parent_n = _norm(child), _norm(parent)
    if child_n == parent_n:
        return True
    sep = os.sep
    return child_n.startswith(parent_n.rstrip(sep) + sep)


def _system_locations() -> tuple[list[Path], list[Path]]:
    exact: list[Path] = []
    subtree: list[Path] = []
    if sys.platform == "win32":
        env = os.environ
        for key in ("WINDIR", "SYSTEMROOT", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "PROGRAMDATA"):
            value = env.get(key)
            if value:
                subtree.append(Path(value))
        for key in ("APPDATA", "LOCALAPPDATA"):
            value = env.get(key)
            if value:
                subtree.append(Path(value))
        system_drive = env.get("SYSTEMDRIVE", "C:")
        exact.append(Path(system_drive + "\\Users"))
    else:
        for item in ("/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys", "/lib", "/lib32",
                     "/lib64", "/libx32", "/root", "/run", "/snap", "/System", "/private/etc", "/private/var/db",
                     "/Library", "/Applications", "/cores"):
            subtree.append(Path(item))
        for item in ("/var", "/opt", "/home", "/Users", "/mnt", "/media", "/srv", "/tmp", "/private",
                     "/Volumes"):
            exact.append(Path(item))
    return exact, subtree


def validate_share_folder(folder: Path, data_dir: Path) -> Path:
    resolved = folder.expanduser().resolve()
    if resolved.exists() and not resolved.is_dir():
        raise FolderRejected("not_directory")
    if resolved.parent == resolved or _norm(resolved) == _norm(Path(resolved.anchor)):
        raise FolderRejected("filesystem_root")
    home = Path.home().resolve()
    if _is_within(home, resolved):
        raise FolderRejected("home_or_ancestor")
    data_resolved = data_dir.resolve()
    if _is_within(data_resolved, resolved) or _is_within(resolved, data_resolved):
        raise FolderRejected("app_data")
    if _is_within(resolved, home):
        relative_parts = resolved.relative_to(home).parts
        if any(part.startswith(".") for part in relative_parts):
            raise FolderRejected("hidden_config")
        if sys.platform == "win32" and relative_parts and relative_parts[0].lower() == "appdata":
            raise FolderRejected("hidden_config")
        if sys.platform == "darwin" and relative_parts and relative_parts[0] == "Library":
            raise FolderRejected("hidden_config")
    inside_home = _is_within(resolved, home)
    exact, subtree = _system_locations()
    for location in exact:
        if _norm(resolved) == _norm(location):
            raise FolderRejected("system_location")
    if not inside_home:
        for location in subtree:
            if _is_within(resolved, location):
                raise FolderRejected("system_location")
    try:
        resolved.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FolderRejected("not_writable") from exc
    if _norm(resolved.resolve()) != _norm(resolved) or not resolved.is_dir():
        raise FolderRejected("not_directory")
    try:
        with tempfile.NamedTemporaryFile(dir=resolved, prefix=".lumendrop_probe_", delete=True):
            pass
    except OSError as exc:
        raise FolderRejected("not_writable") from exc
    return resolved


def disk_free_bytes(path: Path) -> int:
    import shutil

    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 0
