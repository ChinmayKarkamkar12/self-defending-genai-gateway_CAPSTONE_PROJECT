"""Create (or reset the password of) a dashboard admin.

Usage (from gateway/):
    python -m scripts.create_admin <username>
        prompts for the password twice (not echoed)
    python -m scripts.create_admin <username> --password-stdin
        reads it from standard input, for scripted setups:
        echo "$ADMIN_PASSWORD" | python -m scripts.create_admin admin --password-stdin

Only a salted scrypt hash is stored. Passwords must be at least
MIN_PASSWORD_LENGTH characters. Existing sessions of a user whose password
is reset stay valid until they expire (LIMITATIONS.md L8-1).
"""
import argparse
import asyncio
import getpass
import re
import sys

from sqlalchemy import select

from app.core.admin_auth import MIN_PASSWORD_LENGTH, hash_password
from app.db.models import AdminUser
from app.db.session import async_session_maker, engine

_USERNAME = re.compile(r"[A-Za-z0-9._-]{3,64}")


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != first:
        sys.exit("passwords don't match")
    return first


async def create_admin(username: str, password: str) -> bool:
    """Returns True if a new admin was created, False if one was updated."""
    async with async_session_maker() as session:
        user = (
            await session.execute(select(AdminUser).where(AdminUser.username == username))
        ).scalar_one_or_none()
        created = user is None
        if created:
            user = AdminUser(username=username, password_hash=hash_password(password))
            session.add(user)
        else:
            user.password_hash = hash_password(password)
            user.disabled = False
        await session.commit()
    await engine.dispose()
    return created


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or reset a dashboard admin.")
    parser.add_argument("username")
    parser.add_argument("--password-stdin", action="store_true")
    args = parser.parse_args()

    if not _USERNAME.fullmatch(args.username):
        sys.exit("username must be 3-64 characters: letters, digits, '.', '_' or '-'")
    password = _read_password(args.password_stdin)
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"password must be at least {MIN_PASSWORD_LENGTH} characters")

    created = asyncio.run(create_admin(args.username, password))
    print(f"{'Created' if created else 'Updated'} admin '{args.username}'.")


if __name__ == "__main__":
    main()
