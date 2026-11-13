from __future__ import annotations

import math
import queue
import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, unquote_to_bytes

from lumendrop.config import SecurityPolicy


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    hard_reject: bool = False


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: float
    client: str
    reason: str
    weight: float


_OVERLONG = re.compile(r"%(c0|c1|e0%80|f0%80%80)%", re.IGNORECASE)
_DOUBLE_ENCODED = re.compile(r"%25(2e|2f|5c|00|0d|0a|25)", re.IGNORECASE)
_SCANNER_PATHS = re.compile(
    r"(/\.env\b|/\.git(/|$)|/\.svn|/\.hg|/\.ds_store|/\.aws|/\.ssh|/\.htaccess|/\.htpasswd|/wp-(admin|login|content|includes)"
    r"|/xmlrpc\.php|/phpmyadmin|/pma/|/adminer|/cgi-bin/|/actuator|/server-status|/etc/passwd|/proc/self"
    r"|/boaform|/hnap1|/vendor/phpunit|/solr/|/jenkins|/manager/html|/console/|/owa/|/autodiscover"
    r"|/\.vscode|/config\.json$|/web\.config|/backup\.(zip|sql|tar)|/dump\.sql|/shell\b|/cmd\.(php|aspx?)"
    r"|\.(php|asp|aspx|jsp|cgi|pl)$)",
    re.IGNORECASE,
)
_BENIGN_MISSING = re.compile(
    r"^/(favicon\.ico|robots\.txt|apple-touch-icon[\w\-]*\.png|browserconfig\.xml|\.well-known/[\w\-./]{1,80}"
    r"|sitemap\.xml|ads\.txt|humans\.txt|security\.txt)$",
    re.IGNORECASE,
)
_SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nuclei|masscan|zgrab|gobuster|dirbuster|dirb/|wpscan|nmap|acunetix|nessus|openvas|"
    r"w3af|arachni|feroxbuster|ffuf|wfuzz|hydra|medusa|jaeles|whatweb|zmeu|morfeus|paros|burpcollaborator|"
    r"interactsh|commix|xsstrike)",
    re.IGNORECASE,
)
_JNDI = re.compile(r"\$\{\s*(jndi|\$\{|lower:|upper:|env:|sys:|::-)", re.IGNORECASE)
_INJECTION_FAMILIES: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(
        r"(\bunion\b[\s/*+]+(all[\s/*+]+)?select\b|'\s*or\s+'?\d+'?\s*=\s*'?\d+|\bsleep\s*\(\s*\d+\s*\)|"
        r"\bbenchmark\s*\(|\bwaitfor\s+delay\b|\binformation_schema\b|;\s*(drop|truncate|shutdown)\s+\w+|"
        r"\bpg_sleep\s*\(|\bextractvalue\s*\(|\bupdatexml\s*\()",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"(<\s*script\b|javascript\s*:|vbscript\s*:|\bon(error|load|mouseover|focus|click|toggle|begin)\s*=|"
        r"<\s*(svg|img|iframe|body|details|object|embed)\b[^>]*\bon\w+\s*=|<\s*iframe\b|srcdoc\s*=|"
        r"document\.(cookie|domain)|\balert\s*\()",
        re.IGNORECASE,
    ),
    "template": re.compile(r"(\{\{.{0,80}\}\}|\{%.{0,80}%\}|#\{.{0,80}\}|<%=.{0,80}%>)", re.DOTALL),
    "command": re.compile(
        r"([;&|`]\s*(cat|id|whoami|uname|curl|wget|nc|ncat|bash|sh|zsh|powershell|cmd|ping|nslookup)\b|"
        r"\$\(\s*\w+|\|\|\s*\w+\s|`[^`]{1,60}`)",
        re.IGNORECASE,
    ),
    "file_probe": re.compile(r"(/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|\bc:\\windows\\|/proc/self/)", re.IGNORECASE),
}
_FREE_TEXT_KEYS = {"q"}
_DISALLOWED_METHODS = {"TRACE", "TRACK", "CONNECT", "DEBUG", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"}
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}


def _segments(text: str) -> list[str]:
    return re.split(r"[/\\]", text)


def inspect_path(raw_path: bytes) -> list[Signal]:
    signals: list[Signal] = []
    try:
        raw = raw_path.decode("ascii")
    except UnicodeDecodeError:
        raw = raw_path.decode("latin-1")
        signals.append(Signal("non_ascii_path", 0.4))
    lowered = raw.lower()
    if _OVERLONG.search(raw):
        signals.append(Signal("overlong_utf8", 4.0, True))
    if _DOUBLE_ENCODED.search(raw):
        signals.append(Signal("double_encoding", 3.0, True))
    try:
        once_bytes = unquote_to_bytes(raw)
        once = once_bytes.decode("utf-8")
    except UnicodeDecodeError:
        signals.append(Signal("invalid_utf8", 1.5, True))
        once = unquote(raw, errors="replace")
    twice = unquote(once, errors="replace")
    if "\x00" in once or "%00" in lowered:
        signals.append(Signal("null_byte", 4.0, True))
    if "\r" in once or "\n" in once:
        signals.append(Signal("crlf_injection", 3.0, True))
    if ".." in _segments(raw) or ".." in _segments(once) or ".." in _segments(twice):
        signals.append(Signal("path_traversal", 4.0, True))
    if _JNDI.search(once):
        signals.append(Signal("jndi_lookup", 5.0, True))
    return signals


def inspect_query(query_string: bytes, max_length: int) -> list[Signal]:
    if not query_string:
        return []
    signals: list[Signal] = []
    try:
        query = query_string.decode("ascii")
    except UnicodeDecodeError:
        query = query_string.decode("latin-1")
        signals.append(Signal("non_ascii_query", 0.4))
    if len(query) > max_length:
        signals.append(Signal("oversized_query", 1.5, True))
        return signals
    if _OVERLONG.search(query) or _DOUBLE_ENCODED.search(query):
        signals.append(Signal("query_encoding_evasion", 3.0, True))
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=32, errors="strict")
    except (ValueError, UnicodeDecodeError):
        signals.append(Signal("malformed_query", 1.5, True))
        return signals
    families_hit: dict[str, float] = {}
    for key, value in pairs:
        for text in (key, value):
            if "\x00" in text or "\r" in text or "\n" in text:
                signals.append(Signal("query_control_chars", 2.5, True))
            if _JNDI.search(text):
                signals.append(Signal("jndi_lookup", 5.0, True))
        weight = 1.0 if key in _FREE_TEXT_KEYS else 2.0
        for family, pattern in _INJECTION_FAMILIES.items():
            if pattern.search(value) or pattern.search(key):
                families_hit[family] = max(families_hit.get(family, 0.0), weight)
    for family, weight in families_hit.items():
        signals.append(Signal(f"{family}_pattern", weight))
    return signals


def inspect_headers(headers: dict[str, str], authenticated: bool) -> list[Signal]:
    signals: list[Signal] = []
    agent = headers.get("user-agent", "")
    if _SCANNER_UA.search(agent):
        signals.append(Signal("scanner_user_agent", 3.0))
    elif not agent and not authenticated:
        signals.append(Signal("missing_user_agent", 0.3))
    for name, value in headers.items():
        if name in ("cookie",):
            continue
        if _JNDI.search(value):
            signals.append(Signal("jndi_lookup", 5.0, True))
            break
    return signals


def inspect_method(method: str) -> list[Signal]:
    if method in ALLOWED_METHODS:
        return []
    if method in _DISALLOWED_METHODS:
        return [Signal("disallowed_method", 2.5, True)]
    return [Signal("unknown_method", 1.5, True)]


def status_signals(path: str, status: int, authenticated: bool) -> list[Signal]:
    if status == 404:
        if _BENIGN_MISSING.match(path):
            return []
        if _SCANNER_PATHS.search(path):
            return [Signal("scanner_probe", 1.0 if authenticated else 3.0)]
        return [Signal("not_found", 0.15 if authenticated else 0.6)]
    if status == 405:
        return [Signal("method_not_allowed", 0.3 if authenticated else 0.8)]
    return []


def _logit(p: float) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)
    return math.log(p / (1 - p))


class ThreatDetector:
    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy
        self._decay = math.log(2) / max(policy.threat_half_life, 1.0)
        self._prior = _logit(policy.threat_prior_probability)
        self._threshold = _logit(policy.threat_ban_probability)
        self._scores: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def accumulate(self, key: str, weight: float, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        with self._lock:
            score, updated = self._scores.pop(key, (0.0, now))
            score = score * math.exp(-self._decay * max(0.0, now - updated)) + weight
            self._scores[key] = (score, now)
            while len(self._scores) > self.policy.max_tracked_clients:
                self._scores.popitem(last=False)
            return score

    def current(self, key: str, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        with self._lock:
            entry = self._scores.get(key)
            if entry is None:
                return 0.0
            score, updated = entry
            return score * math.exp(-self._decay * max(0.0, now - updated))

    def posterior(self, score: float, prior_shift: float = 0.0) -> float:
        z = self._prior + prior_shift + score
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def should_ban(self, score: float, prior_shift: float = 0.0) -> bool:
        return self._prior + prior_shift + score >= self._threshold

    def reset(self, key: str) -> None:
        with self._lock:
            self._scores.pop(key, None)


class SecurityEventBus:
    def __init__(self, maxlen: int = 300) -> None:
        self._events: deque[SecurityEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._subscribers: list["queue.Queue[SecurityEvent]"] = []

    def publish(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)
            subscribers = list(self._subscribers)
        for sink in subscribers:
            try:
                sink.put_nowait(event)
            except queue.Full:
                pass

    def subscribe(self, maxsize: int = 1000) -> "queue.Queue[SecurityEvent]":
        sink: "queue.Queue[SecurityEvent]" = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.append(sink)
        return sink

    def unsubscribe(self, sink: "queue.Queue[SecurityEvent]") -> None:
        with self._lock:
            if sink in self._subscribers:
                self._subscribers.remove(sink)

    def recent(self) -> list[SecurityEvent]:
        with self._lock:
            return list(self._events)
