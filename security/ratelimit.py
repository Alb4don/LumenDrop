from __future__ import annotations

import ipaddress
import threading
import time
from collections import OrderedDict


def client_key(ip: str | None) -> str:
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip[:64]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        if addr.is_loopback:
            return "::1"
        return str(ipaddress.IPv6Network(f"{addr}/64", strict=False))
    return str(addr)


class TokenBucketLimiter:
    def __init__(self, capacity: float, refill_per_second: float, max_keys: int = 20_000) -> None:
        self.capacity = float(capacity)
        self.refill = float(refill_per_second)
        self.max_keys = max_keys
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str, cost: float = 1.0, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, updated = self._buckets.pop(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - updated) * self.refill)
            if tokens >= cost:
                tokens -= cost
                retry_after = 0.0
            else:
                retry_after = (cost - tokens) / self.refill if self.refill > 0 else 60.0
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return retry_after

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)
