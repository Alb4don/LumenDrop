from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Limits:
    max_upload_bytes: int = 20 * 1024 ** 3
    io_block: int = 1024 * 1024
    min_chunk: int = 256 * 1024
    max_chunk: int = 64 * 1024 * 1024
    default_chunk: int = 8 * 1024 * 1024
    upload_session_ttl: int = 24 * 3600
    max_uploads_per_session: int = 32
    max_uploads_total: int = 256
    disk_reserve_bytes: int = 512 * 1024 * 1024
    max_filename_length: int = 200
    max_json_body: int = 16 * 1024
    max_form_body: int = 4 * 1024
    max_url_length: int = 4096
    page_size_default: int = 200
    page_size_max: int = 500
    thumb_size: int = 320
    thumb_max_source_bytes: int = 80 * 1024 * 1024
    thumb_max_pixels: int = 60_000_000
    thumb_workers: int = 2


@dataclass(frozen=True)
class SecurityPolicy:
    pin_length: int = 8
    session_idle_seconds: int = 2 * 3600
    session_absolute_seconds: int = 12 * 3600
    max_sessions: int = 512
    login_attempts_per_window: int = 5
    login_window_seconds: int = 900
    global_login_failure_budget: int = 20
    anon_rate_capacity: float = 60.0
    anon_rate_refill: float = 2.0
    auth_rate_capacity: float = 600.0
    auth_rate_refill: float = 40.0
    ban_base_seconds: int = 1800
    ban_escalation: tuple[int, ...] = (1, 4, 48)
    threat_half_life: float = 180.0
    threat_prior_probability: float = 0.01
    threat_ban_probability: float = 0.985
    authenticated_prior_shift: float = -1.5
    trusted_prior_shift: float = -1.0
    event_retention_days: int = 30
    max_tracked_clients: int = 20_000


@dataclass(frozen=True)
class Settings:
    share_folder: Path
    host: str = "0.0.0.0"
    port: int = 8420
    use_https: bool = True
    allow_root: bool = False
    advertise_address: str | None = None
    extra_hostnames: tuple[str, ...] = ()
    data_dir: Path | None = None
    limits: Limits = field(default_factory=Limits)
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)

    def resolved_data_dir(self) -> Path:
        return self.data_dir if self.data_dir is not None else app_data_dir()


def app_data_dir() -> Path:
    override = os.environ.get("LUMENDROP_DATA_DIR")
    if override:
        target = Path(override).expanduser()
    elif sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        target = Path(base) / "LumenDrop"
    elif sys.platform == "darwin":
        target = Path.home() / "Library" / "Application Support" / "LumenDrop"
    else:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
        target = Path(base) / "LumenDrop"
    ensure_private_dir(target)
    return target


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path
