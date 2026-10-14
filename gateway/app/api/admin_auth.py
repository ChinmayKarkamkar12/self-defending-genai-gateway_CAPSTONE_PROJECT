"""Dashboard admin login (module 8). See app/core/admin_auth.py.

    POST /v1/admin/auth/login    {username, password} -> session token
    POST /v1/admin/auth/logout   ends the current session
    GET  /v1/admin/auth/me       who is logged in

The only /v1/admin routes reachable without a session are login itself
(app/main.py adds `require_admin` to every other admin router).
"""
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.admin_auth import (
    AdminPrincipal,
    bearer_token,
    clear_failures,
    create_session,
    end_session,
    login_locked,
    record_failure,
    require_admin,
    verify_password_async,
)
from app.core.governance.redis_client import get_redis
from app.db.models import AdminUser
from app.db.session import get_db

router = APIRouter(prefix="/v1/admin/auth")

INVALID_LOGIN_DETAIL = "wrong username or password"


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class LoginOut(BaseModel):
    token: str
    username: str
    expires_at: datetime


class MeOut(BaseModel):
    username: str


@router.post("/login", response_model=LoginOut)
async def login(
    body: LoginIn,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
    redis: Redis = Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> LoginOut:
    try:
        if await login_locked(redis, body.username):
            raise HTTPException(
                status_code=429,
                detail="too many failed logins for this username; try again later",
            )
        user = (
            await db.execute(select(AdminUser).where(AdminUser.username == body.username))
        ).scalar_one_or_none()
        stored = user.password_hash if user is not None and not user.disabled else None
        if not await verify_password_async(body.password, stored):
            await record_failure(redis, body.username)
            raise HTTPException(status_code=401, detail=INVALID_LOGIN_DETAIL)
        await clear_failures(redis, body.username)
        token = await create_session(
            redis, AdminPrincipal(user_id=user.id, username=user.username)
        )
    except RedisError:
        raise HTTPException(status_code=503, detail="admin sessions unavailable") from None
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.ADMIN_SESSION_TTL_SECONDS)
    return LoginOut(token=token, username=user.username, expires_at=expires_at)


@router.post("/logout", status_code=204)
async def logout(
    authorization: Annotated[str | None, Header()] = None,
    _admin: AdminPrincipal = Depends(require_admin),  # noqa: B008 - standard FastAPI DI pattern
    redis: Redis = Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> Response:
    await end_session(redis, bearer_token(authorization))
    return Response(status_code=204)


@router.get("/me", response_model=MeOut)
async def me(
    admin: AdminPrincipal = Depends(require_admin),  # noqa: B008 - standard FastAPI DI pattern
) -> MeOut:
    return MeOut(username=admin.username)
