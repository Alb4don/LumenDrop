from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass
from importlib import resources

from lumendrop.i18n import WEB_STRINGS

_JS_STRING_KEYS = (
    "gallery_empty", "no_results", "download", "delete", "delete_confirm", "deleted", "copy_hash", "copied",
    "quarantine_badge", "uploading", "queued", "paused_offline", "retrying", "verifying", "done", "failed", "cancel",
    "cancelled", "leave_warning", "free_space", "showing", "server_error", "file_too_large", "session_expired",
)


@dataclass(frozen=True)
class Asset:
    body: bytes
    media_type: str
    digest: str


def _load(name: str, media_type: str) -> Asset:
    body = resources.files("lumendrop.web").joinpath("static", name).read_bytes()
    return Asset(body=body, media_type=media_type, digest=hashlib.sha256(body).hexdigest()[:16])


CSS = _load("app.css", "text/css; charset=utf-8")
JS = _load("app.js", "text/javascript; charset=utf-8")
ICON = _load("icon.svg", "image/svg+xml")

ASSET_ROUTES = {
    f"app-{CSS.digest}.css": CSS,
    f"app-{JS.digest}.js": JS,
    f"icon-{ICON.digest}.svg": ICON,
}


def page_csp(nonce: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'self'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "require-trusted-types-for 'script'"
    )


def _e(value: str) -> str:
    return html.escape(value, quote=True)


def _head(lang: str, title: str, extra: str = "") -> str:
    return (
        f'<!doctype html><html lang="{_e(lang)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="dark"><meta name="referrer" content="same-origin">'
        f"<title>{_e(title)}</title>"
        f'<link rel="stylesheet" href="/assets/app-{CSS.digest}.css">'
        f'<link rel="icon" type="image/svg+xml" href="/assets/icon-{ICON.digest}.svg">'
        f"{extra}</head>"
    )


def render_lang_switch(lang: str) -> str:
    links = []
    for code, label in (("en", "EN"), ("pt", "PT-BR")):
        cls = "active" if code == lang else ""
        links.append(f'<a class="{cls}" href="/lang/{code}" hreflang="{code}">{label}</a>')
    return f'<span class="lang-switch">{"".join(links)}</span>'


def render_login_page(lang: str, nonce_value: str, pin_length: int, error: str = "") -> str:
    t = WEB_STRINGS[lang]
    return (
        _head(lang, t["page_title"])
        + '<body data-page="login"><main class="container login-wrap"><div class="card login-card">'
        f'<div class="topbar"><div class="brand"><img src="/assets/icon-{ICON.digest}.svg" alt="">'
        f'<h1>{_e(t["page_title"])}</h1></div>{render_lang_switch(lang)}</div>'
        f'<p>{_e(t["login_heading"])}</p>'
        '<form method="post" action="/login" autocomplete="off">'
        f'<input type="hidden" name="nonce" value="{_e(nonce_value)}">'
        f'<input type="password" inputmode="numeric" pattern="[0-9]*" minlength="{pin_length}" maxlength="{pin_length}" '
        f'name="pin" placeholder="{_e(t["login_placeholder"])}" aria-label="{_e(t["login_heading"])}" '
        'autocomplete="one-time-code" autofocus required>'
        f'<button type="submit">{_e(t["login_button"])}</button></form>'
        f'<div class="error-text" role="alert">{_e(error)}</div>'
        "</div></main></body></html>"
    )


def _json_for_script(data: dict) -> str:
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render_main_page(lang: str, csrf_token: str, nonce: str, client_config: dict) -> str:
    t = WEB_STRINGS[lang]
    config = dict(client_config)
    config["strings"] = {key: t[key] for key in _JS_STRING_KEYS}
    sort_options = "".join(
        f'<option value="{value}">{_e(t[label])}</option>'
        for value, label in (("newest", "sort_newest"), ("oldest", "sort_oldest"), ("name", "sort_name"), ("size", "sort_size"))
    )
    return (
        _head(lang, t["page_title"], f'<meta name="csrf-token" content="{_e(csrf_token)}">')
        + '<body data-page="main"><main class="container">'
        f'<div class="topbar"><div class="brand"><img src="/assets/icon-{ICON.digest}.svg" alt="">'
        f'<h1>{_e(t["page_title"])}</h1></div>'
        f'<div class="topbar-right"><span class="muted" id="freeSpace"></span>{render_lang_switch(lang)}'
        f'<button type="button" class="link-button" id="logoutButton">{_e(t["logout"])}</button></div></div>'
        f'<div class="net-banner" id="netBanner" role="status" hidden>{_e(t["paused_offline"])}</div>'
        f'<div class="dropzone" id="dropzone" role="button" tabindex="0" aria-label="{_e(t["drop_zone_text"])}">'
        f'<p>{_e(t["drop_zone_text"])}</p><p class="hint">{_e(t["drop_zone_hint"])}</p>'
        '<input type="file" id="fileInput" multiple hidden></div>'
        '<div class="uploads" id="uploadList" aria-live="polite"></div>'
        f'<div class="toolbar"><h2>{_e(t["gallery_heading"])}</h2>'
        '<span class="muted" id="fileCount"></span>'
        f'<input type="search" id="searchInput" maxlength="200" placeholder="{_e(t["search_placeholder"])}" '
        f'aria-label="{_e(t["search_placeholder"])}">'
        f'<select id="sortSelect" aria-label="Sort">{sort_options}</select></div>'
        '<div class="file-grid" id="fileGrid"></div>'
        f'<div class="empty-state" id="emptyState" hidden>{_e(t["gallery_empty"])}</div>'
        f'<button type="button" class="load-more" id="loadMore" hidden>{_e(t["load_more"])}</button>'
        "</main>"
        '<div class="toasts" id="toasts"></div>'
        f'<script type="application/json" id="ld-config">{_json_for_script(config)}</script>'
        f'<script nonce="{_e(nonce)}" src="/assets/app-{JS.digest}.js"></script>'
        "</body></html>"
    )
