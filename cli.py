from __future__ import annotations

import argparse
import logging
import queue
import signal
import sys
import threading
from pathlib import Path

from lumendrop import APP_NAME, APP_VERSION
from lumendrop.config import Limits, SecurityPolicy, Settings, ensure_private_dir
from lumendrop.i18n import FOLDER_REJECTION_REASONS
from lumendrop.logging_setup import build_logger
from lumendrop.paths import FolderRejected
from lumendrop.server import ServerController, is_elevated_privileges


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535")
    return port


def _pin_length(value: str) -> int:
    try:
        length = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("PIN length must be an integer") from exc
    if not 6 <= length <= 12:
        raise argparse.ArgumentTypeError("PIN length must be between 6 and 12")
    return length


def _hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or not all(c.isalnum() or c in ".-" for c in value):
        raise argparse.ArgumentTypeError("invalid hostname")
    return value


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="lumendrop", description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("folder", nargs="?", default=str(Path.home() / "LumenDrop"))
    parser.add_argument("--port", type=_port, default=8420)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--advertise", default=None)
    parser.add_argument("--hostname", action="append", type=_hostname, default=[])
    parser.add_argument("--pin-length", type=_pin_length, default=8)
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--allow-root", action="store_true")
    parser.add_argument("--no-gui", action="store_true")
    parser.add_argument("--no-https", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return parser.parse_args(argv)


def build_settings(args: argparse.Namespace) -> Settings:
    data_dir = Path(args.data_dir).expanduser() if args.data_dir else None
    return Settings(
        share_folder=Path(args.folder).expanduser(),
        host=args.host,
        port=args.port,
        use_https=not args.no_https,
        allow_root=args.allow_root,
        advertise_address=args.advertise,
        extra_hostnames=tuple(args.hostname),
        data_dir=data_dir,
        limits=Limits(),
        policy=SecurityPolicy(pin_length=args.pin_length),
    )


def run_headless(settings: Settings, logger: logging.Logger) -> int:
    try:
        controller = ServerController(settings, logger)
    except FolderRejected as exc:
        reason = FOLDER_REJECTION_REASONS["en"].get(exc.code, exc.code)
        print(f"Refusing to share {settings.share_folder}: {reason}", file=sys.stderr)
        return 2

    def announce_pin(new_pin: str, reason: str) -> None:
        print(f"\n[!] PIN rotated automatically ({reason}). New PIN: {new_pin}\n", flush=True)

    controller.ctx.pins.on_rotate(announce_pin)
    info = controller.info
    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Folder: {controller.share_folder}")
    print(f"URL:    {info.url}")
    for extra in info.urls[1:]:
        print(f"        {extra}")
    print(f"PIN:    {controller.ctx.pins.pin}")
    if info.fingerprint:
        print(f"TLS certificate fingerprint (SHA-256): {info.fingerprint}")
    elif info.https_requested:
        print("HTTPS unavailable this run; serving over plain HTTP. See the log for details.")
    print("No internet connection is required; devices only need to share a network with this computer.", flush=True)

    if not controller.start():
        controller.stop()
        print("Failed to start server. The port may be in use or permission was denied.", file=sys.stderr)
        return 1

    stop_event = threading.Event()

    def _handle_signal(signum, frame) -> None:
        stop_event.set()

    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _handle_signal)
            except (ValueError, OSError):
                pass
    try:
        while controller.running and not stop_event.is_set():
            stop_event.wait(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
    return 0


def main(argv: list[str] | None = None) -> None:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    settings = build_settings(args)
    data_dir = ensure_private_dir(settings.resolved_data_dir())
    gui_queue: "queue.Queue[str] | None" = None if args.no_gui else queue.Queue(maxsize=5000)
    logger = build_logger(data_dir, gui_queue, logging.DEBUG if args.verbose else logging.INFO)

    if is_elevated_privileges() and not args.allow_root:
        logger.warning("Detected administrator/root privileges. Restart without elevation, or pass --allow-root.")
        if args.no_gui:
            sys.exit(1)

    if args.no_gui:
        sys.exit(run_headless(settings, logger))

    from lumendrop.gui import run_gui

    run_gui(settings, logger, gui_queue)


if __name__ == "__main__":
    main()
