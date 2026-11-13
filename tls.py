from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from lumendrop import APP_NAME
from lumendrop.config import ensure_private_dir

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

CERT_VALIDITY_DAYS = 397
RENEW_BEFORE_DAYS = 30
STRONG_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!3DES"


@dataclass(frozen=True)
class CertificateInfo:
    cert_path: Path
    key_path: Path
    fingerprint: str


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    if os.name == "posix":
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def _not_valid_after(cert) -> datetime.datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _san_values(cert) -> tuple[set[str], set[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set(), set()
    ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    dns = {name.lower() for name in san.get_values_for_type(x509.DNSName)}
    return ips, dns


def _desired_names(ip_addresses: list[str]) -> tuple[set[str], set[str]]:
    ips = {"127.0.0.1", "::1"}
    for value in ip_addresses:
        try:
            ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    dns = {"localhost"}
    try:
        hostname = socket.gethostname().lower().rstrip(".")
        if hostname and all(part and len(part) < 64 for part in hostname.split(".")):
            short = hostname.split(".")[0]
            dns.update({hostname, short, f"{short}.local"})
    except OSError:
        pass
    return ips, dns


def _load_or_create_key(key_path: Path):
    if key_path.exists():
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if isinstance(key, ec.EllipticCurvePrivateKey):
                return key, False
        except (ValueError, TypeError, OSError):
            pass
    return ec.generate_private_key(ec.SECP256R1()), True


def _build_certificate(key, ips: set[str], dns: set[str]):
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{APP_NAME} local server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, APP_NAME),
    ])
    san_entries: list = [x509.DNSName(d) for d in sorted(dns)]
    san_entries += [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )


def ensure_certificate(cert_dir: Path, ip_addresses: list[str], logger: logging.Logger) -> CertificateInfo | None:
    if not CRYPTOGRAPHY_AVAILABLE:
        logger.warning("The 'cryptography' package is not installed; HTTPS is unavailable this run.")
        return None
    try:
        ensure_private_dir(cert_dir)
        cert_path = cert_dir / "cert.pem"
        key_path = cert_dir / "key.pem"
        key, key_is_new = _load_or_create_key(key_path)
        want_ips, want_dns = _desired_names(ip_addresses)

        cert = None
        if not key_is_new and cert_path.exists():
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            except (ValueError, OSError):
                cert = None

        regenerate = cert is None
        if cert is not None:
            remaining = _not_valid_after(cert) - datetime.datetime.now(datetime.timezone.utc)
            have_ips, have_dns = _san_values(cert)
            same_key = cert.public_key().public_numbers() == key.public_key().public_numbers()
            if remaining < datetime.timedelta(days=RENEW_BEFORE_DAYS):
                regenerate = True
            elif not want_ips <= have_ips or not want_dns <= have_dns or not same_key:
                regenerate = True

        if key_is_new:
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            _atomic_write(key_path, key_bytes, 0o600)

        if regenerate:
            logger.info("Generating a new self-signed TLS certificate (%s address(es))", len(want_ips))
            cert = _build_certificate(key, want_ips, want_dns)
            _atomic_write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)

        fingerprint = ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))
        return CertificateInfo(cert_path=cert_path, key_path=key_path, fingerprint=fingerprint)
    except Exception:
        logger.exception("TLS certificate preparation failed; falling back to HTTP.")
        return None


def harden_ssl_context(context: ssl.SSLContext | None) -> None:
    if context is None:
        return
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.set_ciphers(STRONG_CIPHERS)
    except ssl.SSLError:
        pass
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    context.options |= getattr(ssl, "OP_CIPHER_SERVER_PREFERENCE", 0)
    context.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    context.options |= getattr(ssl, "OP_SINGLE_ECDH_USE", 0)
