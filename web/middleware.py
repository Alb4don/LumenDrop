from __future__ import annotations

import ipaddress
import json
import math
import re
import secrets

from starlette.requests import cookie_parser

from lumendrop.i18n import WEB_STRINGS, pick_language
from lumendrop.netinfo import normalize_host
from lumendrop.security.detector import (
    Signal,
    inspect_headers,
    inspect_method,
    inspect_path,
    inspect_query,
    status_signals,
)
from lumendrop.security.ratelimit import client_key
from lumendrop.web.context import AppContext

MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_COUNT = 100
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CHUNK_ROUTE = re.compile(r"^/api/uploads/[A-Za-z0-9_-]{1,64}/chunks/\d{1,9}$")
_DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


class BodyTooLarge(Exception):
    pass


def _route_cost(method: str, path: str) -> float:
    if path.startswith("/thumbs/") or path.startswith("/assets/"):
        return 0.25
    if method == "POST" and path == "/login":
        return 3.0
    return 1.0


def _body_limit(ctx: AppContext, method: str, path: str) -> int:
    limits = ctx.settings.limits
    if method == "PUT" and _CHUNK_ROUTE.match(path):
        return limits.max_chunk
    if method == "POST" and path == "/login":
        return limits.max_form_body
    if method in UNSAFE_METHODS:
        return limits.max_json_body
    return 0


class SecurityMiddleware:
    def __init__(self, app, ctx: AppContext) -> None:
        self.app = app
        self.ctx = ctx
        policy = ctx.settings.policy
        self._security_headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"same-origin"),
            (b"permissions-policy", b"geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"cross-origin-resource-policy", b"same-origin"),
            (b"origin-agent-cluster", b"?1"),
            (b"x-permitted-cross-domain-policies", b"none"),
        ]
        if ctx.https:
            self._security_headers.append((b"strict-transport-security", b"max-age=31536000"))
        self._auth_shift = policy.authenticated_prior_shift

    async def _reject(self, send, status: int, key: str, lang: str, retry_after: float = 0.0) -> None:
        body = json.dumps({"detail": WEB_STRINGS[lang].get(key, WEB_STRINGS[lang]["invalid_request"]), "code": key}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
            (b"content-security-policy", _DEFAULT_CSP.encode()),
            (b"connection", b"close"),
        ] + self._security_headers
        if retry_after > 0:
            headers.append((b"retry-after", str(max(1, math.ceil(retry_after))).encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            return

        ctx = self.ctx
        headers: dict[str, str] = {}
        host_values: list[str] = []
        raw_headers = scope.get("headers", [])
        if len(raw_headers) > MAX_HEADER_COUNT or sum(len(n) + len(v) for n, v in raw_headers) > MAX_HEADER_BYTES:
            await self._reject(send, 431, "invalid_request", "en")
            return
        for raw_name, raw_value in raw_headers:
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            if name == "host":
                host_values.append(value)
            if name not in headers:
                headers[name] = value
        lang = pick_language(None, headers.get("accept-language"))
        client_ip = scope.get("client")[0] if scope.get("client") else None
        client = client_key(client_ip)
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")
        raw_path = scope.get("raw_path") or path.encode("utf-8", "surrogateescape")
        query = scope.get("query_string", b"") or b""

        banned_for = ctx.bans.is_banned(client)
        if banned_for:
            await self._reject(send, 403, "forbidden", lang, banned_for)
            return

        cookies = cookie_parser(headers.get("cookie", "")) if "cookie" in headers else {}
        lang = pick_language(cookies.get(ctx.lang_cookie), headers.get("accept-language"))
        session = ctx.sessions.get(cookies.get(ctx.session_cookie), headers.get("user-agent", ""), touch=False)
        authenticated = session is not None

        signals: list[Signal] = []
        reject_status, reject_key = 0, "invalid_request"
        limits = ctx.settings.limits

        if len(raw_path) + len(query) > limits.max_url_length:
            signals.append(Signal("oversized_url", 1.5, True))
        signals += inspect_method(method)
        signals += inspect_path(raw_path)
        signals += inspect_query(query, limits.max_url_length)
        signals += inspect_headers(headers, authenticated)

        if len(host_values) != 1 or not ctx.hosts.is_allowed(host_values[0]):
            host = normalize_host(host_values[0]) if host_values else None
            is_ip_literal = False
            if host:
                try:
                    ipaddress.ip_address(host)
                    is_ip_literal = True
                except ValueError:
                    pass
            signals.append(Signal("unexpected_host", 0.3 if is_ip_literal else 2.0, True))
            reject_status, reject_key = 421, "forbidden"

        fetch_site = headers.get("sec-fetch-site", "")
        if fetch_site in ("cross-site", "same-site"):
            if method in UNSAFE_METHODS:
                signals.append(Signal("cross_site_write", 2.5, True))
                reject_status, reject_key = 403, "forbidden"
            elif not (headers.get("sec-fetch-mode") == "navigate" and method == "GET"
                      and headers.get("sec-fetch-dest", "document") in ("document", "")):
                signals.append(Signal("cross_site_resource", 0.5, True))
                reject_status, reject_key = 403, "forbidden"

        if method in UNSAFE_METHODS and not any(s.name == "unexpected_host" for s in signals):
            scheme = "https" if scope.get("scheme") == "https" else "http"
            expected_origin = f"{scheme}://{host_values[0].strip().lower()}" if host_values else ""
            origin = headers.get("origin")
            referer = headers.get("referer")
            if origin is not None:
                if origin.strip().lower() != expected_origin:
                    signals.append(Signal("origin_mismatch", 2.5, True))
                    reject_status, reject_key = 403, "forbidden"
            elif referer is not None:
                normalized = referer.strip().lower()
                if not (normalized == expected_origin or normalized.startswith(expected_origin + "/")):
                    signals.append(Signal("referer_mismatch", 2.0, True))
                    reject_status, reject_key = 403, "forbidden"

        if signals:
            if ctx.report(client, signals, authenticated, path):
                await self._reject(send, 403, "forbidden", lang)
                return
            if any(s.hard_reject for s in signals):
                status = reject_status or (405 if any(s.name.endswith("method") for s in signals) else 400)
                await self._reject(send, status, reject_key, lang)
                return

        limiter = ctx.auth_limiter if authenticated else ctx.anon_limiter
        bucket = f"s:{session.session_id}" if authenticated else f"a:{client}"
        retry_after = limiter.take(bucket, _route_cost(method, path))
        if retry_after > 0:
            if not authenticated:
                ctx.report(client, [Signal("rate_limited", 0.5)], False, path)
            await self._reject(send, 429, "rate_limited", lang, retry_after)
            return

        limit = _body_limit(ctx, method, path)
        declared = headers.get("content-length")
        if declared is not None:
            if not declared.isdigit() or len(declared) > 15:
                await self._reject(send, 400, "invalid_request", lang)
                return
            if int(declared) > limit:
                if not authenticated:
                    ctx.report(client, [Signal("oversized_body", 1.0)], False, path)
                await self._reject(send, 413, "file_too_large", lang)
                return
        if "transfer-encoding" in headers and declared is not None:
            await self._reject(send, 400, "invalid_request", lang)
            return

        consumed = 0

        async def limited_receive():
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > limit:
                    raise BodyTooLarge()
            return message

        status_holder = {"status": 0}
        nonce_holder = {"value": None}
        scope.setdefault("state", {})
        scope["state"]["csp_nonce"] = secrets.token_urlsafe(16)
        nonce_holder["value"] = scope["state"]["csp_nonce"]
        scope["state"]["client_key"] = client
        scope["state"]["lang"] = lang

        async def secured_send(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                existing = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(n, v) for n, v in self._security_headers if n not in existing]
                if b"cache-control" not in existing:
                    extra.append((b"cache-control", b"no-store"))
                if b"content-security-policy" not in existing:
                    extra.append((b"content-security-policy", _DEFAULT_CSP.encode()))
                message = dict(message)
                message["headers"] = [
                    (n, v) for n, v in message.get("headers", []) if n.lower() not in (b"server", b"x-powered-by")
                ] + extra
            await send(message)

        await self.app(scope, limited_receive, secured_send)

        follow_up = status_signals(path, status_holder["status"], authenticated)
        if follow_up:
            ctx.report(client, follow_up, authenticated, path)
