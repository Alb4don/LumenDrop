from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass

try:
    import psutil
except ImportError:
    psutil = None

_VIRTUAL_IFACE = re.compile(
    r"(docker|veth|br-|virbr|vmnet|vboxnet|vethernet|virtualbox|vmware|hyper-v|wsl|utun|awdl|llw|"
    r"bridge|tap|tun|anpi|ap\d|lxc|lxd|cni|flannel|cali|kube|podman)",
    re.IGNORECASE,
)
_ROUTE_PROBES = (
    ("8.8.8.8", 80),
    ("1.1.1.1", 80),
    ("10.255.255.255", 1),
    ("172.31.255.255", 1),
    ("192.168.255.255", 1),
    ("169.254.255.255", 1),
)


@dataclass(frozen=True)
class LocalAddress:
    ip: str
    interface: str
    score: int
    kind: str

    @property
    def label(self) -> str:
        return f"{self.ip}  ({self.interface}, {self.kind})" if self.interface else f"{self.ip}  ({self.kind})"


def _kind(ip: ipaddress.IPv4Address) -> str:
    if ip.is_link_local:
        return "link-local"
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat-vpn"
    if ip.is_private:
        return "lan"
    return "public"


def _route_sources() -> set[str]:
    found: set[str] = set()
    for target in _ROUTE_PROBES:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.2)
            sock.connect(target)
            found.add(sock.getsockname()[0])
        except OSError:
            pass
        finally:
            sock.close()
    return found


def _psutil_addresses() -> list[tuple[str, str]]:
    if psutil is None:
        return []
    results: list[tuple[str, str]] = []
    try:
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            iface_stats = stats.get(name)
            if iface_stats is not None and not iface_stats.isup:
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address:
                    results.append((addr.address, name))
    except Exception:
        return []
    return results


def _hostname_addresses() -> list[str]:
    results: list[str] = []
    for host in {socket.gethostname()}:
        try:
            for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
                results.append(info[4][0])
        except OSError:
            continue
    return results


def discover_addresses() -> list[LocalAddress]:
    route_sources = _route_sources()
    candidates: dict[str, tuple[str, set[str]]] = {}
    for ip_text, iface in _psutil_addresses():
        candidates.setdefault(ip_text, (iface, set()))[1].add("iface")
    for ip_text in _hostname_addresses():
        iface, origins = candidates.setdefault(ip_text, ("", set()))
        origins.add("hostname")
    for ip_text in route_sources:
        iface, origins = candidates.setdefault(ip_text, ("", set()))
        origins.add("route")

    ranked: list[LocalAddress] = []
    for ip_text, (iface, origins) in candidates.items():
        try:
            ip = ipaddress.IPv4Address(ip_text)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            continue
        kind = _kind(ip)
        score = {"lan": 50, "cgnat-vpn": 30, "public": 25, "link-local": 15}[kind]
        if "route" in origins:
            score += 20
        if "iface" in origins:
            score += 5
        if iface and _VIRTUAL_IFACE.search(iface):
            score -= 40
        ranked.append(LocalAddress(ip=ip_text, interface=iface, score=score, kind=kind))
    ranked.sort(key=lambda item: (-item.score, item.ip))
    return ranked


def primary_address(preferred: str | None = None) -> str:
    addresses = discover_addresses()
    if preferred:
        for item in addresses:
            if item.ip == preferred:
                return preferred
    return addresses[0].ip if addresses else "127.0.0.1"


class HostAllowlist:
    def __init__(self, extra_hostnames: tuple[str, ...] = (), refresh_seconds: float = 30.0,
                 min_forced_interval: float = 5.0) -> None:
        self._extra = {h.lower().rstrip(".") for h in extra_hostnames if h}
        self._refresh_seconds = refresh_seconds
        self._min_forced_interval = min_forced_interval
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._last_compute = 0.0
        self._cached: frozenset[str] = self._compute()
        self._thread: threading.Thread | None = None

    def _compute(self) -> frozenset[str]:
        names = {"localhost", "127.0.0.1", "::1"}
        try:
            hostname = socket.gethostname().lower().rstrip(".")
            if hostname:
                short = hostname.split(".")[0]
                names.update({hostname, short, f"{short}.local"})
        except OSError:
            pass
        try:
            for item in discover_addresses():
                names.add(item.ip)
        except Exception:
            pass
        names |= self._extra
        self._last_compute = time.monotonic()
        return frozenset(names)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="lumendrop-hosts", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self._refresh_seconds)
            self._wake.clear()
            if self._stop.is_set():
                break
            fresh = self._compute()
            with self._lock:
                self._cached = fresh

    def allowed(self) -> frozenset[str]:
        with self._lock:
            return self._cached

    def is_allowed(self, host_header: str | None) -> bool:
        host = normalize_host(host_header)
        if host is None:
            return False
        if host in self.allowed():
            return True
        if time.monotonic() - self._last_compute >= self._min_forced_interval:
            self._wake.set()
        return False


def normalize_host(host_header: str | None) -> str | None:
    if not host_header or len(host_header) > 255:
        return None
    host = host_header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            return None
        inner = host[1:end]
        rest = host[end + 1:]
        if rest and not re.fullmatch(r":\d{1,5}", rest):
            return None
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return None
        return inner
    if host.count(":") == 1:
        host, _, port = host.partition(":")
        if not port.isdigit() or len(port) > 5:
            return None
    elif host.count(":") > 1:
        return None
    host = host.rstrip(".")
    if not re.fullmatch(r"[a-z0-9_.\-]{1,253}", host):
        return None
    return host
