"""Dashboard admin authentication (module 8). Closes LIMITATIONS.md L3-1,
L6a-4 and L7-7: every /v1/admin route requires a logged-in admin.

Passwords: salted scrypt (Python's standard library, no extra dependency),
stored as `scrypt$<n>$<r>$<p>$<salt>$<hash>` so the cost can be raised later
without breaking existing hashes. Checking one takes ~50 ms of CPU, so it
runs in a worker thread rather than on the event loop.

Sessions: logging in returns a random 256-bit token. Redis keeps only the
token's SHA-256, under `admin:session:<sha256>`, with a TTL
(ADMIN_SESSION_TTL_SECONDS) - a Redis dump does not contain usable tokens.
Logging out deletes the key.

Brute force: each failed login for a username increments
`admin:login_failures:<username>`; at ADMIN_LOGIN_MAX_FAILURES the username
is refused (429) until the counter expires (ADMIN_LOGIN_LOCK_SECONDS). An
unknown username costs the same password check as a known one, so response
time doesn't reveal which usernames exist.

Fail-closed: if Redis is unreachable, admin requests get 503, never access.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.config import settings
from app.core.governance.redis_client import get_redis

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
MIN_PASSWORD_LENGTH = 12

# Checked against when the username doesn't exist, so that path costs the
# same as a real check. Its password is random and never stored.
_DUMMY_HASH: str | None = None


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = _unb64(digest)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    return _DUMMY_HASH


async def verify_password_async(password: str, stored: str | None) -> bool:
    """Off the event loop. `stored=None` (unknown user) still does the work."""
    ok = await asyncio.to_thread(verify_password, password, stored or dummy_hash())
    return ok and stored is not None


@dataclass(frozen=True)
class AdminPrincipal:
    user_id: UUID
    username: str


def _token_key(token: str) -> str:
    return "admin:session:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _failures_key(username: str) -> str:
    return f"admin:login_failures:{username.lower()}"


async def create_session(redis: Redis, principal: AdminPrincipal) -> str:
    token = secrets.token_urlsafe(32)
    value = json.dumps({"user_id": str(principal.user_id), "username": principal.username})
    await redis.set(_token_key(token), value, ex=settings.ADMIN_SESSION_TTL_SECONDS)
    return token


async def read_session(redis: Redis, token: str) -> AdminPrincipal | None:
    raw = await redis.get(_token_key(token))
    if raw is None:
        return None
    data = json.loads(raw)
    return AdminPrincipal(user_id=UUID(data["user_id"]), username=data["username"])


async def end_session(redis: Redis, token: str) -> None:
    await redis.delete(_token_key(token))


async def login_locked(redis: Redis, username: str) -> bool:
    failures = await redis.get(_failures_key(username))
    return failures is not None and int(failures) >= settings.ADMIN_LOGIN_MAX_FAILURES


async def record_failure(redis: Redis, username: str) -> None:
    key = _failures_key(username)
    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(key)
        pipe.expire(key, settings.ADMIN_LOGIN_LOCK_SECONDS)
        await pipe.execute()


async def clear_failures(redis: Redis, username: str) -> None:
    await redis.delete(_failures_key(username))


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="admin login required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization.removeprefix("Bearer ").strip()


async def require_admin(
    authorization: Annotated[str | None, Header()] = None,
    redis: Redis = Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> AdminPrincipal:
    """FastAPI dependency on every /v1/admin route (wired in app/main.py)."""
    token = bearer_token(authorization)
    try:
        principal = await read_session(redis, token)
    except RedisError:
        raise HTTPException(status_code=503, detail="admin sessions unavailable") from None
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="admin session expired or invalid; log in again",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal
