"""Module 8: dashboard admin authentication. Every /v1/admin route except
login requires a logged-in admin (closes LIMITATIONS.md L3-1, L6a-4, L7-7)."""
import re

import pytest
from redis.exceptions import RedisError

from app.config import settings
from app.core import admin_auth
from app.core.admin_auth import hash_password, verify_password
from app.db.models import AdminUser
from app.main import app

PASSWORD = "correct horse battery staple"


async def _add_admin(db_session, username="alice", password=PASSWORD, disabled=False):
    user = AdminUser(username=username, password_hash=hash_password(password), disabled=disabled)
    db_session.add(user)
    await db_session.commit()
    return user


async def _login(client, username="alice", password=PASSWORD):
    return await client.post(
        "/v1/admin/auth/login", json={"username": username, "password": password}
    )


def _admin_routes() -> list[tuple[str, str]]:
    # From the OpenAPI schema: every endpoint the app really serves,
    # however its routers are nested.
    return [
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        if path.startswith("/v1/admin")
        for method in operations
    ]


def test_password_hashing():
    stored = hash_password(PASSWORD)
    assert stored.startswith("scrypt$")
    assert PASSWORD not in stored
    assert verify_password(PASSWORD, stored)
    assert not verify_password(PASSWORD + "!", stored)
    # Salted: the same password never hashes the same way twice.
    assert hash_password(PASSWORD) != stored
    assert not verify_password(PASSWORD, "garbage")


async def test_every_admin_route_requires_login(anon_client):
    routes = _admin_routes()
    assert len(routes) > 15  # sanity: the routes were actually found
    for method, path in routes:
        if path == "/v1/admin/auth/login":
            continue
        url = re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)
        response = await anon_client.request(method, url, json={})
        assert response.status_code == 401, f"{method} {path} -> {response.status_code}"


async def test_login_then_use_admin_api(anon_client, db_session):
    await _add_admin(db_session)

    response = await _login(anon_client)
    assert response.status_code == 200
    token = response.json()["token"]
    auth = {"Authorization": f"Bearer {token}"}

    assert (await anon_client.get("/v1/admin/teams", headers=auth)).status_code == 200
    me = await anon_client.get("/v1/admin/auth/me", headers=auth)
    assert me.json() == {"username": "alice"}


async def test_wrong_password_and_unknown_user_look_the_same(anon_client, db_session):
    await _add_admin(db_session)

    wrong = await _login(anon_client, password="not the password")
    unknown = await _login(anon_client, username="mallory")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_disabled_admin_cannot_log_in(anon_client, db_session):
    await _add_admin(db_session, disabled=True)
    assert (await _login(anon_client)).status_code == 401


async def test_repeated_failures_lock_the_username(anon_client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_LOGIN_MAX_FAILURES", 3)
    await _add_admin(db_session)

    for _ in range(3):
        assert (await _login(anon_client, password="guess")).status_code == 401
    # Locked: even the right password is refused until the counter expires.
    assert (await _login(anon_client)).status_code == 429


async def test_successful_login_resets_the_failure_count(anon_client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_LOGIN_MAX_FAILURES", 3)
    await _add_admin(db_session)

    for _ in range(2):
        await _login(anon_client, password="guess")
    assert (await _login(anon_client)).status_code == 200
    for _ in range(2):
        await _login(anon_client, password="guess")
    assert (await _login(anon_client)).status_code == 200


async def test_logout_ends_the_session(anon_client, db_session):
    await _add_admin(db_session)
    token = (await _login(anon_client)).json()["token"]
    auth = {"Authorization": f"Bearer {token}"}

    assert (await anon_client.post("/v1/admin/auth/logout", headers=auth)).status_code == 204
    assert (await anon_client.get("/v1/admin/teams", headers=auth)).status_code == 401


async def test_session_expires(anon_client, db_session, fake_redis):
    await _add_admin(db_session)
    token = (await _login(anon_client)).json()["token"]
    [key] = await fake_redis.keys("admin:session:*")
    assert 0 < await fake_redis.ttl(key) <= settings.ADMIN_SESSION_TTL_SECONDS

    await fake_redis.delete(key)  # what the TTL does when it runs out
    response = await anon_client.get(
        "/v1/admin/teams", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


async def test_redis_holds_only_a_hash_of_the_token(anon_client, db_session, fake_redis):
    await _add_admin(db_session)
    token = (await _login(anon_client)).json()["token"]

    for key in await fake_redis.keys("*"):
        assert token not in key
        value = await fake_redis.get(key) if await fake_redis.type(key) == "string" else ""
        assert token not in (value or "")
        assert PASSWORD not in (value or "")


async def test_forged_token_rejected(anon_client):
    response = await anon_client.get(
        "/v1/admin/teams", headers={"Authorization": "Bearer made-up-token"}
    )
    assert response.status_code == 401


async def test_redis_down_fails_closed(anon_client, monkeypatch):
    async def broken(*args, **kwargs):
        raise RedisError("down")

    monkeypatch.setattr(admin_auth, "read_session", broken)
    response = await anon_client.get(
        "/v1/admin/teams", headers={"Authorization": "Bearer anything"}
    )
    assert response.status_code == 503


@pytest.mark.parametrize("body", [{}, {"username": "", "password": "x"}, {"username": "a"}])
async def test_login_validates_body(anon_client, body):
    response = await anon_client.post("/v1/admin/auth/login", json=body)
    assert response.status_code == 422
