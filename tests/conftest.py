from __future__ import annotations

import logging
import re

import pytest
from starlette.testclient import TestClient

from lumendrop.config import Limits, SecurityPolicy, Settings
from lumendrop.logging_setup import build_logger
from lumendrop.paths import validate_share_folder
from lumendrop.web.app import create_app
from lumendrop.web.context import AppContext


@pytest.fixture()
def env(tmp_path):
    data_dir = tmp_path / "data"
    share = tmp_path / "share"
    share.mkdir()
    data_dir.mkdir()
    settings = Settings(
        share_folder=share,
        use_https=False,
        extra_hostnames=("testserver",),
        data_dir=data_dir,
        limits=Limits(min_chunk=64 * 1024, default_chunk=64 * 1024, disk_reserve_bytes=0),
        policy=SecurityPolicy(pin_length=8),
    )
    logger = build_logger(data_dir, None, logging.INFO, console=False)
    folder = validate_share_folder(share, data_dir)
    ctx = AppContext.build(settings, folder, logger, https=False, initial_pin="48213957")
    app = create_app(ctx)
    with TestClient(app, base_url="http://testserver") as client:
        yield ctx, client, share
    ctx.close()


def login(client: TestClient, pin: str = "48213957"):
    page = client.get("/login")
    nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
    return client.post("/login", data={"pin": pin, "nonce": nonce}, follow_redirects=False)


def csrf_of(client: TestClient) -> str:
    page = client.get("/")
    return re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)


@pytest.fixture()
def authed(env):
    ctx, client, share = env
    response = login(client)
    assert response.status_code == 303
    token = csrf_of(client)
    client.headers.update({"X-CSRF-Token": token})
    return ctx, client, share
