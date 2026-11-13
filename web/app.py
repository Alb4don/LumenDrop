from __future__ import annotations

import asyncio
import mimetypes
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, Path as PathParam, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect

from lumendrop.i18n import WEB_STRINGS, pick_language
from lumendrop.logging_setup import safe_repr
from lumendrop.security.auth import Session
from lumendrop.security.detector import SecurityEvent, Signal
from lumendrop.security.filescan import RASTER_IMAGE_KINDS
from lumendrop.paths import disk_free_bytes
from lumendrop.storage.uploads import UploadError, is_valid_upload_id
from lumendrop.web.assets import ASSET_ROUTES, page_csp, render_login_page, render_main_page
from lumendrop.web.context import AppContext
from lumendrop.web.middleware import BodyTooLarge, SecurityMiddleware

MAINTENANCE_INTERVAL_SECONDS = 300
_PASSIVE_MIME = {
    "png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp",
}
_SAFE_ATTACHMENT_TYPES = {
    "application/pdf", "application/zip", "text/plain", "text/csv", "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel", "application/vnd.ms-powerpoint", "application/epub+zip",
}


class AuthRequired(Exception):
    pass


class CsrfFailed(Exception):
    pass


class UploadInit(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    filename: str = Field(min_length=1, max_length=1024)
    total_size: int = Field(gt=0)
    chunk_size: int | None = Field(default=None, gt=0)


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def lang_of(request: Request) -> str:
    state_lang = getattr(request.state, "lang", None)
    if state_lang in WEB_STRINGS:
        return state_lang
    ctx = get_ctx(request)
    return pick_language(request.cookies.get(ctx.lang_cookie), request.headers.get("accept-language"))


def client_of(request: Request) -> str:
    return getattr(request.state, "client_key", None) or "unknown"


def error_response(request: Request, key: str, status: int, extra: dict | None = None) -> JSONResponse:
    lang = lang_of(request)
    payload = {"detail": WEB_STRINGS[lang].get(key, WEB_STRINGS[lang]["invalid_request"]), "code": key}
    if extra:
        payload.update(extra)
    return JSONResponse(payload, status_code=status)


def optional_session(request: Request) -> Session | None:
    ctx = get_ctx(request)
    return ctx.sessions.get(request.cookies.get(ctx.session_cookie), request.headers.get("user-agent", ""))


def require_session(request: Request) -> Session:
    session = optional_session(request)
    if session is None:
        raise AuthRequired()
    return session


def require_csrf(request: Request, session: Session = Depends(require_session)) -> Session:
    token = request.headers.get("x-csrf-token", "")
    if not token or len(token) > 128 or not secrets.compare_digest(token, session.csrf_token):
        raise CsrfFailed()
    return session


def _set_cookie(response: Response, ctx: AppContext, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name, value, max_age=max_age, path="/", httponly=True, samesite="strict", secure=ctx.https,
    )


def _html(content: str, nonce: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(content, status_code=status, headers={"Content-Security-Policy": page_csp(nonce)})


def _safe_back_path(referer: str | None, request: Request) -> str:
    if not referer:
        return "/"
    try:
        parts = urlsplit(referer)
    except ValueError:
        return "/"
    host = request.headers.get("host", "").lower()
    if parts.netloc.lower() != host or parts.scheme not in ("http", "https"):
        return "/"
    path = parts.path or "/"
    if not path.startswith("/") or path.startswith("//") or "\\" in path or path.startswith("/lang/"):
        return "/"
    return path if path in ("/", "/login") else "/"


def build_pages_router() -> APIRouter:
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        ctx = get_ctx(request)
        session = optional_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        limits = ctx.settings.limits
        config = {
            "lang": lang_of(request),
            "pageSize": limits.page_size_default,
            "maxUpload": limits.max_upload_bytes,
            "chunk": {"min": limits.min_chunk, "max": limits.max_chunk, "preferred": limits.default_chunk},
        }
        nonce = request.state.csp_nonce
        return _html(render_main_page(lang_of(request), session.csrf_token, nonce, config), nonce)

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        ctx = get_ctx(request)
        if optional_session(request) is not None:
            return RedirectResponse("/", status_code=303)
        return _login_response(request, ctx, "", 200)

    @router.post("/login")
    async def login_submit(request: Request):
        ctx = get_ctx(request)
        lang = lang_of(request)
        t = WEB_STRINGS[lang]
        client = client_of(request)
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in ("application/x-www-form-urlencoded", "multipart/form-data"):
            return error_response(request, "invalid_request", 415)
        try:
            form = await request.form(max_files=0, max_fields=4, max_part_size=1024)
        except Exception:
            return error_response(request, "invalid_request", 400)
        pin = form.get("pin")
        nonce_value = form.get("nonce")
        if not isinstance(pin, str) or not isinstance(nonce_value, str):
            return _login_response(request, ctx, t["login_error"], 400)
        if not ctx.nonces.verify(nonce_value, request.cookies.get(ctx.nonce_cookie)):
            ctx.report(client, [Signal("login_nonce_invalid", 0.8)], False, "/login")
            return _login_response(request, ctx, t["login_expired"], 400)
        decision = await run_in_threadpool(ctx.pins.verify, client, pin)
        if not decision.ok:
            if decision.reason == "locked":
                minutes = max(1, -(-decision.retry_after // 60))
                response = _login_response(request, ctx, t["login_locked"].format(minutes=minutes), 429)
                response.headers["Retry-After"] = str(decision.retry_after)
                return response
            if decision.reason == "paused":
                response = _login_response(request, ctx, t["login_paused"], 429)
                response.headers["Retry-After"] = str(decision.retry_after)
                return response
            ctx.logger.warning("Failed sign-in attempt from %s", client)
            ctx.report(client, [Signal("login_failure", 0.8)], False, "/login")
            await asyncio.sleep(0.35 + secrets.randbelow(250) / 1000)
            return _login_response(request, ctx, t["login_error"], 401)
        ctx.sessions.revoke(request.cookies.get(ctx.session_cookie))
        token, _ = ctx.sessions.create(client, request.headers.get("user-agent", ""))
        ctx.detector.reset(client)
        ctx.logger.info("Successful sign-in from %s", client)
        response = RedirectResponse("/", status_code=303)
        _set_cookie(response, ctx, ctx.session_cookie, token, ctx.settings.policy.session_absolute_seconds)
        response.delete_cookie(ctx.nonce_cookie, path="/", secure=ctx.https, httponly=True, samesite="strict")
        return response

    @router.post("/logout")
    async def logout(request: Request, session: Session = Depends(require_csrf)):
        ctx = get_ctx(request)
        ctx.sessions.revoke(request.cookies.get(ctx.session_cookie))
        response = JSONResponse({"ok": True})
        response.delete_cookie(ctx.session_cookie, path="/", secure=ctx.https, httponly=True, samesite="strict")
        return response

    @router.get("/lang/{code}")
    async def switch_lang(request: Request, code: str = PathParam(max_length=8)):
        ctx = get_ctx(request)
        if code not in WEB_STRINGS:
            code = "en"
        response = RedirectResponse(_safe_back_path(request.headers.get("referer"), request), status_code=303)
        _set_cookie(response, ctx, ctx.lang_cookie, code, 365 * 24 * 3600)
        return response

    @router.get("/assets/{name}")
    async def asset(name: str = PathParam(max_length=64)):
        item = ASSET_ROUTES.get(name)
        if item is None:
            raise StarletteHTTPException(status_code=404)
        return Response(item.body, media_type=item.media_type,
                        headers={"Cache-Control": "public, max-age=31536000, immutable"})

    @router.get("/favicon.ico")
    async def favicon():
        return Response(status_code=204, headers={"Cache-Control": "public, max-age=86400"})

    @router.get("/robots.txt")
    async def robots():
        return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")

    @router.api_route("/api/health", methods=["GET", "HEAD"])
    async def health():
        return {"status": "ok"}

    return router


def _login_response(request: Request, ctx: AppContext, error: str, status: int) -> HTMLResponse:
    nonce_value = ctx.nonces.issue()
    csp_nonce = request.state.csp_nonce
    response = _html(
        render_login_page(lang_of(request), nonce_value, ctx.settings.policy.pin_length, error), csp_nonce, status,
    )
    _set_cookie(response, ctx, ctx.nonce_cookie, nonce_value, 900)
    return response


def build_api_router() -> APIRouter:
    router = APIRouter()

    @router.get("/api/files")
    async def list_files(
        request: Request,
        session: Session = Depends(require_session),
        q: str = Query(default="", max_length=200),
        sort: str = Query(default="newest", pattern="^(newest|oldest|name|size)$"),
        offset: int = Query(default=0, ge=0, le=10_000_000),
        limit: int = Query(default=200, ge=1, le=500),
    ):
        ctx = get_ctx(request)
        items, total = await run_in_threadpool(ctx.files.list, q, sort, offset, limit)
        free = await run_in_threadpool(disk_free_bytes, ctx.files.folder)
        limits = ctx.settings.limits
        return {
            "items": [item.to_public(ctx.files.thumbs_enabled, limits.thumb_max_source_bytes) for item in items],
            "total": total,
            "free_bytes": free,
        }

    @router.delete("/api/files/{name}")
    async def delete_file(request: Request, name: str = PathParam(max_length=512), session: Session = Depends(require_csrf)):
        ctx = get_ctx(request)
        deleted = await run_in_threadpool(ctx.files.delete, name)
        if not deleted:
            return error_response(request, "not_found", 404)
        ctx.logger.info("Deleted by %s: %s", client_of(request), safe_repr(name))
        return {"ok": True}

    @router.api_route("/files/{name}", methods=["GET", "HEAD"])
    async def download(
        request: Request,
        name: str = PathParam(max_length=512),
        session: Session = Depends(require_session),
    ):
        ctx = get_ctx(request)
        entry = await run_in_threadpool(ctx.files.entry, name)
        if entry is None:
            return error_response(request, "not_found", 404)
        path = ctx.files.folder / entry.name
        force_download = "download" in request.query_params
        inline = entry.is_raster_image and not force_download
        if inline:
            media_type = _PASSIVE_MIME[entry.kind]
        else:
            guessed = mimetypes.guess_type(entry.name)[0] or ""
            if entry.kind in RASTER_IMAGE_KINDS and guessed.startswith("image/"):
                media_type = _PASSIVE_MIME[entry.kind]
            elif guessed in _SAFE_ATTACHMENT_TYPES or guessed.startswith(("audio/", "video/")):
                media_type = guessed
            else:
                media_type = "application/octet-stream"
        headers = {
            "Content-Security-Policy": "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox",
            "Cache-Control": "private, max-age=300" if inline else "private, no-cache",
            "X-Download-Options": "noopen",
        }
        return FileResponse(
            path, media_type=media_type, filename=entry.name, headers=headers,
            content_disposition_type="inline" if inline else "attachment",
        )

    @router.get("/thumbs/{name}")
    async def thumbnail(request: Request, name: str = PathParam(max_length=512), session: Session = Depends(require_session)):
        ctx = get_ctx(request)
        thumb = await run_in_threadpool(ctx.files.thumbnail, name)
        if thumb is None:
            return Response(status_code=204)
        return FileResponse(thumb, media_type="image/jpeg", headers={
            "Cache-Control": "private, max-age=86400",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        })

    @router.post("/api/uploads")
    async def upload_init(request: Request, payload: UploadInit, session: Session = Depends(require_csrf)):
        ctx = get_ctx(request)
        limits = ctx.settings.limits
        if payload.total_size > limits.max_upload_bytes:
            return error_response(request, "file_too_large", 413)
        created = await run_in_threadpool(
            ctx.uploads.create, session.session_id, payload.filename, payload.total_size, payload.chunk_size,
        )
        ctx.logger.info("Upload started by %s: %s (%s bytes, %s chunk(s))", client_of(request),
                        safe_repr(created["filename"]), payload.total_size, created["total_chunks"])
        return created

    @router.get("/api/uploads/{upload_id}")
    async def upload_status(request: Request, upload_id: str = PathParam(max_length=64),
                            session: Session = Depends(require_session)):
        _check_upload_id(request, upload_id)
        ctx = get_ctx(request)
        return await run_in_threadpool(ctx.uploads.status, upload_id)

    @router.put("/api/uploads/{upload_id}/chunks/{index}")
    async def upload_chunk(
        request: Request,
        upload_id: str = PathParam(max_length=64),
        index: int = PathParam(ge=0, le=10_000_000),
        session: Session = Depends(require_csrf),
    ):
        _check_upload_id(request, upload_id)
        ctx = get_ctx(request)
        declared = request.headers.get("content-length")
        declared_length = int(declared) if declared and declared.isdigit() else None
        return await ctx.uploads.write_chunk(
            upload_id, index, request.stream(), declared_length, request.headers.get("x-chunk-sha256"),
        )

    @router.post("/api/uploads/{upload_id}/complete")
    async def upload_complete(request: Request, upload_id: str = PathParam(max_length=64),
                              session: Session = Depends(require_csrf)):
        _check_upload_id(request, upload_id)
        ctx = get_ctx(request)
        client = client_of(request)
        result = await run_in_threadpool(ctx.uploads.finalize, upload_id)
        if result["quarantined"]:
            reason = f"flagged_upload:{','.join(result['reasons'])}"
            ctx.logger.warning("Upload flagged for review from %s: %s (%s)", client, safe_repr(result["name"]),
                               ",".join(result["reasons"]))
            ctx.bus.publish(SecurityEvent(time.time(), client, reason, 0.0))
        ctx.logger.info("Upload saved from %s: %s (%s bytes)", client, safe_repr(result["name"]), result["size"])
        return result

    @router.delete("/api/uploads/{upload_id}")
    async def upload_cancel(request: Request, upload_id: str = PathParam(max_length=64),
                            session: Session = Depends(require_csrf)):
        _check_upload_id(request, upload_id)
        ctx = get_ctx(request)
        cancelled = await run_in_threadpool(ctx.uploads.cancel, upload_id)
        return {"ok": cancelled}

    return router


class InvalidUploadId(Exception):
    pass


def _check_upload_id(request: Request, upload_id: str) -> None:
    if not is_valid_upload_id(upload_id):
        raise InvalidUploadId()


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthRequired)
    async def on_auth_required(request: Request, exc: AuthRequired):
        if request.url.path.startswith("/api/") or request.method not in ("GET", "HEAD"):
            return error_response(request, "session_expired", 401)
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(CsrfFailed)
    async def on_csrf(request: Request, exc: CsrfFailed):
        ctx = get_ctx(request)
        ctx.report(client_of(request), [Signal("csrf_failure", 1.5)], True, request.url.path)
        return error_response(request, "forbidden", 403)

    @app.exception_handler(InvalidUploadId)
    async def on_bad_upload_id(request: Request, exc: InvalidUploadId):
        ctx = get_ctx(request)
        ctx.report(client_of(request), [Signal("invalid_upload_id", 1.0)], True, request.url.path)
        return error_response(request, "invalid_request", 400)

    @app.exception_handler(UploadError)
    async def on_upload_error(request: Request, exc: UploadError):
        key = exc.code if exc.code in WEB_STRINGS["en"] else "invalid_request"
        if exc.code == "checksum_mismatch":
            key = "invalid_request"
        return error_response(request, key, exc.status, {"code": exc.code})

    @app.exception_handler(ClientDisconnect)
    async def on_disconnect(request: Request, exc: ClientDisconnect):
        return Response(status_code=499)

    @app.exception_handler(BodyTooLarge)
    async def on_body_too_large(request: Request, exc: BodyTooLarge):
        return error_response(request, "file_too_large", 413)

    @app.exception_handler(RequestValidationError)
    async def on_validation(request: Request, exc: RequestValidationError):
        return error_response(request, "invalid_request", 400)

    @app.exception_handler(StarletteHTTPException)
    async def on_http(request: Request, exc: StarletteHTTPException):
        mapping = {404: "not_found", 405: "invalid_request", 413: "file_too_large", 429: "rate_limited"}
        key = mapping.get(exc.status_code, "invalid_request" if exc.status_code < 500 else "server_error")
        return error_response(request, key, exc.status_code)

    @app.exception_handler(Exception)
    async def on_unexpected(request: Request, exc: Exception):
        ref = secrets.token_hex(4)
        get_ctx(request).logger.exception("Unhandled error ref=%s on %s %s", ref, request.method,
                                          safe_repr(request.url.path))
        return error_response(request, "server_error", 500, {"ref": ref})


def create_app(ctx: AppContext) -> SecurityMiddleware:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ctx.hosts.start()
        await run_in_threadpool(ctx.maintenance)

        async def periodic():
            while True:
                await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)
                await run_in_threadpool(ctx.maintenance)

        task = asyncio.create_task(periodic())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan, redirect_slashes=False)
    app.state.ctx = ctx
    install_error_handlers(app)
    app.include_router(build_pages_router())
    app.include_router(build_api_router())
    return SecurityMiddleware(app, ctx)
