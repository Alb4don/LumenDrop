from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

HEADER_BYTES = 4096

EXECUTABLE_EXTENSIONS = {
    ".exe", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".sh", ".bash", ".zsh", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".jar", ".scr", ".com", ".pif", ".dll", ".sys", ".cpl", ".msc", ".lnk",
    ".reg", ".apk", ".xapk", ".app", ".pkg", ".dmg", ".deb", ".rpm", ".run", ".elf", ".command",
    ".appimage", ".gadget", ".application", ".appx", ".msix", ".iso", ".img", ".vhd", ".vhdx",
}
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".sldm"}
DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif",
    ".mp3", ".mp4", ".mov", ".avi", ".zip", ".rar", ".7z", ".csv", ".odt", ".heic", ".webp",
}
ACTIVE_CONTENT_EXTENSIONS = {".html", ".htm", ".xhtml", ".svg", ".xml", ".mht", ".mhtml"}
RASTER_IMAGE_KINDS = {"png", "jpeg", "gif", "webp", "bmp"}
RASTER_IMAGE_EXTENSIONS = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp", ".bmp": "bmp"}


@dataclass(frozen=True)
class FileVerdict:
    kind: str
    quarantined: bool
    score: int
    reasons: tuple[str, ...]


def read_header(path: Path, length: int = HEADER_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(length)
    except OSError:
        return b""


def _is_pe(header: bytes) -> bool:
    if len(header) < 0x40 or header[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", header, 0x3C)[0]
    if 0x40 <= offset <= len(header) - 4:
        return header[offset:offset + 4] == b"PE\x00\x00"
    return 0 < offset < 0x10000


def sniff_kind(header: bytes) -> str:
    if not header:
        return "empty"
    if _is_pe(header):
        return "pe"
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if header[:4] == b"\xca\xfe\xba\xbe" and len(header) >= 8:
        count = struct.unpack_from(">I", header, 4)[0]
        return "macho" if 0 < count < 45 else "java_class"
    if header.startswith(b"#!"):
        first_line = header.split(b"\n", 1)[0][:200].lower()
        if any(token in first_line for token in (b"sh", b"python", b"perl", b"ruby", b"node", b"php", b"env")):
            return "script"
    if header.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    if header[:2] == b"BM" and len(header) >= 26:
        return "bmp"
    if header.startswith(b"%PDF-"):
        return "pdf"
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        return "zip"
    if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if header.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if header[:2] == b"\x1f\x8b":
        return "gzip"
    if header[4:8] == b"ftyp":
        return "media"
    if header[:4] in (b"ID3\x03", b"ID3\x04") or header[:2] == b"\xff\xfb":
        return "media"
    sample = header[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if sample.startswith((b"<!doctype html", b"<html", b"<script", b"<svg", b"<?xml")) or b"<script" in sample:
        return "markup"
    return "data"


def classify_bytes(name: str, header: bytes) -> FileVerdict:
    suffixes = [s.lower() for s in Path(name).suffixes][-3:]
    ext = suffixes[-1] if suffixes else ""
    kind = sniff_kind(header)
    reasons: list[str] = []
    score = 0
    executable_content = kind in {"pe", "elf", "macho", "script", "lnk"}

    if executable_content and ext not in EXECUTABLE_EXTENSIONS:
        reasons.append(f"disguised_executable:{kind}")
        score += 4
    elif ext in EXECUTABLE_EXTENSIONS:
        reasons.append("executable")
        score += 2

    if len(suffixes) >= 2 and suffixes[-2] in DECOY_EXTENSIONS and ext in EXECUTABLE_EXTENSIONS:
        reasons.append("double_extension")
        score += 3

    if ext in MACRO_EXTENSIONS:
        reasons.append("macro_enabled_document")
        score += 2

    if kind == "markup" and ext not in ACTIVE_CONTENT_EXTENSIONS and ext not in {".txt", ".md", ".log", ".csv", ""}:
        reasons.append("disguised_markup")
        score += 2

    expected_image = RASTER_IMAGE_EXTENSIONS.get(ext)
    if expected_image and kind not in RASTER_IMAGE_KINDS and kind not in {"empty"}:
        reasons.append(f"image_mismatch:{kind}")
        score += 2 if kind in {"markup", "pe", "elf", "macho", "script", "zip"} else 1

    return FileVerdict(kind=kind, quarantined=score >= 2, score=score, reasons=tuple(dict.fromkeys(reasons)))


def classify_file(path: Path) -> FileVerdict:
    return classify_bytes(path.name, read_header(path, HEADER_BYTES))
