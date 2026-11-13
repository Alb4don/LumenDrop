from __future__ import annotations

import ctypes
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass

import uvicorn

from lumendrop.config import Settings, ensure_private_dir
from lumendrop.netinfo import discover_addresses, primary_address
from lumendrop.paths import validate_share_folder
from lumendrop.tls import ensure_certificate, harden_ssl_context
from lumendrop.web.app import create_app
from lumendrop.web.context import AppContext


@dataclass(frozen=True)
class ServerInfo:
    url: str
    urls: tuple[str, ...]
    advertise_ip: str
    fingerprint: str | None
    https_requested: bool
    https_active: bool


def is_elevated_privileges() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def _format_host(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


class ServerController:
    def __init__(self, settings: Settings, logger: logging.Logger, pin: str | None = None) -> None:
        self.settings = settings
        self.logger = logger
        data_dir = ensure_private_dir(settings.resolved_data_dir())
        self.share_folder = validate_share_folder(settings.share_folder, data_dir)
        addresses = [item.ip for item in discover_addresses()]
        advertise = primary_address(settings.advertise_address)
        if settings.advertise_address and settings.advertise_address not in addresses:
            advertise = settings.advertise_address
        cert = None
        if settings.use_https:
            cert = ensure_certificate(data_dir / "tls", sorted(set(addresses) | {advertise}), logger)
        self.cert = cert
        self.ctx = AppContext.build(settings, self.share_folder, logger, https=cert is not None, initial_pin=pin)
        self.app = create_app(self.ctx)
        scheme = "https" if cert is not None else "http"
        port = settings.port
        primary_url = f"{scheme}://{_format_host(advertise)}:{port}/"
        others = [f"{scheme}://{_format_host(ip)}:{port}/" for ip in addresses if ip != advertise]
        self.info = ServerInfo(
            url=primary_url,
            urls=tuple([primary_url] + others),
            advertise_ip=advertise,
            fingerprint=cert.fingerprint if cert else None,
            https_requested=settings.use_https,
            https_active=cert is not None,
        )
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, timeout: float = 10.0) -> bool:
        with self._lock:
            if self.running:
                return True
            kwargs = dict(
                host=self.settings.host,
                port=self.settings.port,
                log_config=None,
                log_level="warning",
                access_log=False,
                server_header=False,
                proxy_headers=False,
                ws="none",
                lifespan="on",
                timeout_keep_alive=15,
                timeout_graceful_shutdown=5,
                limit_concurrency=512,
                backlog=256,
                h11_max_incomplete_event_size=16 * 1024,
            )
            if self.cert is not None:
                kwargs["ssl_certfile"] = str(self.cert.cert_path)
                kwargs["ssl_keyfile"] = str(self.cert.key_path)
            config = uvicorn.Config(self.app, **kwargs)
            config.load()
            harden_ssl_context(config.ssl)
            server = uvicorn.Server(config)
            self._server = server

            def _run() -> None:
                try:
                    server.run()
                except BaseException:
                    self.logger.error("Server thread stopped unexpectedly; see log file for details")
                    self.logger.debug("Server thread failure", exc_info=True)

            thread = threading.Thread(target=_run, name="lumendrop-server", daemon=True)
            self._thread = thread
            thread.start()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and not server.started:
                if not thread.is_alive():
                    break
                time.sleep(0.05)
            if not server.started:
                server.should_exit = True
                thread.join(timeout=2)
                self._thread = None
                self._server = None
                self.logger.error("Server failed to start on port %s", self.settings.port)
                return False
            self.logger.info("Server listening on %s (folder=%s)", self.info.url, self.share_folder)
            return True

    def stop(self) -> None:
        with self._lock:
            server, thread = self._server, self._thread
            if server is not None:
                server.should_exit = True
            if thread is not None:
                thread.join(timeout=8)
                if thread.is_alive() and server is not None:
                    server.force_exit = True
                    thread.join(timeout=3)
            self._server = None
            self._thread = None
            self.ctx.close()
            self.logger.info("Server stopped")
