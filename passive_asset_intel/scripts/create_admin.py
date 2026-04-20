"""Create (or upsert) an admin user.

Usage inside the running app container::

    python -m passive_asset_intel.scripts.create_admin \
        --username admin --password 'somethingStrong' --role admin

If the user exists, its password / role is updated and is_active is forced
true.  Safe to run repeatedly — idempotent by username.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid

import asyncpg

from passive_asset_intel.auth.jwt_handler import hash_password
from passive_asset_intel.utils.config import load_config


async def upsert_user(username: str, password: str, role: str) -> str:
    cfg = load_config()
    conn = await asyncpg.connect(
        host=cfg.db_host, port=cfg.db_port, database=cfg.db_name,
        user=cfg.db_user, password=cfg.db_password,
    )
    try:
        existing = await conn.fetchval(
            "SELECT id FROM users WHERE username = $1", username,
        )
        hashed = hash_password(password)
        if existing:
            await conn.execute(
                """
                UPDATE users
                   SET hashed_password = $1,
                       role = $2,
                       is_active = true,
                       updated_at = NOW()
                 WHERE id = $3
                """,
                hashed, role, existing,
            )
            return f"updated existing user '{username}' (id={existing})"

        new_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO users (id, username, hashed_password, role, is_active)
            VALUES ($1, $2, $3, $4, true)
            """,
            new_id, username, hashed, role,
        )
        return f"created user '{username}' (id={new_id})"
    finally:
        await conn.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Create/update an admin account.")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--role", default="admin", choices=["admin", "analyst"])
    args = p.parse_args()

    if not args.password:
        print("ERROR: password cannot be empty", file=sys.stderr)
        return 2

    msg = asyncio.run(upsert_user(args.username, args.password, args.role))
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
