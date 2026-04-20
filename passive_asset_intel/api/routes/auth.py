"""Authentication endpoints.

Routes:
    POST   /api/auth/login      — exchange username + password for a JWT
    GET    /api/auth/me         — return the current user's info
    GET    /api/auth/users      — (admin) list all users
    POST   /api/auth/users      — (admin) create a new user account
    PATCH  /api/auth/users/{id} — (admin) update role / is_active / password
    DELETE /api/auth/users/{id} — (admin) delete a user
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from passive_asset_intel.api.deps import get_conn
from passive_asset_intel.api.models import TokenResponse, UserCreateRequest, UserInfo
from passive_asset_intel.auth.deps import get_current_user, require_admin
from passive_asset_intel.auth.jwt_handler import (
    create_access_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_VALID_ROLES = {"admin", "analyst"}


class UserUpdateRequest(BaseModel):
    """Request body for PATCH /api/auth/users/{id}."""

    role: Optional[str] = Field(default=None, pattern="^(admin|analyst)$")
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10)


@router.post("/login", response_model=TokenResponse)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Issue a JWT access token on successful username/password authentication.

    Uses the OAuth2 ``application/x-www-form-urlencoded`` form standard so
    Swagger UI's "Authorize" button works out of the box.
    """
    row = await conn.fetchrow(
        "SELECT hashed_password, role, is_active FROM users WHERE username = $1",
        form.username,
    )

    # Constant-time check even if user doesn't exist (prevent user enumeration)
    password_ok = bool(row) and verify_password(form.password, row["hashed_password"] if row else "")

    if not row or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    token = create_access_token({"sub": form.username, "role": row["role"]})
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me", response_model=UserInfo)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Return information about the currently authenticated user."""
    return current_user


@router.post("/users", status_code=201, response_model=UserInfo)
async def create_user(
    body: UserCreateRequest,
    conn: asyncpg.Connection = Depends(get_conn),
    _admin: dict = Depends(require_admin),
):
    """Create a new user account.  Requires the *admin* role.

    The plaintext password is hashed with bcrypt before storage and is never
    persisted or logged.
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=422,
            detail=f"Role must be one of: {sorted(_VALID_ROLES)}",
        )

    try:
        await conn.execute(
            """
            INSERT INTO users (id, username, hashed_password, role, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            """,
            uuid.uuid4(),
            body.username,
            hash_password(body.password),
            body.role,
            datetime.now(timezone.utc).replace(tzinfo=None),
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="Username already exists")

    return {"username": body.username, "role": body.role}


@router.get("/users")
async def list_users(
    conn: asyncpg.Connection = Depends(get_conn),
    _admin: dict = Depends(require_admin),
):
    """List all user accounts.  Requires the *admin* role."""
    rows = await conn.fetch(
        """
        SELECT
            id::text    AS id,
            username,
            role,
            is_active,
            created_at,
            updated_at
        FROM users
        ORDER BY created_at ASC
        """
    )
    return [
        {
            "id": r["id"],
            "username": r["username"],
            "role": r["role"],
            "is_active": r["is_active"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
        }
        for r in rows
    ]


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    body: UserUpdateRequest,
    conn: asyncpg.Connection = Depends(get_conn),
    admin: dict = Depends(require_admin),
):
    """Update a user's role, is_active, or password.  Requires the *admin* role."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user id")

    target = await conn.fetchrow(
        "SELECT username, role, is_active FROM users WHERE id = $1", uid,
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Safety: don't let the last active admin demote / disable themselves.
    if target["role"] == "admin" and (
        (body.role is not None and body.role != "admin")
        or (body.is_active is False)
    ):
        active_admins = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = true",
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote or disable the last active admin",
            )

    sets: list[str] = []
    params: list = []
    idx = 1
    if body.role is not None:
        sets.append(f"role = ${idx}")
        params.append(body.role)
        idx += 1
    if body.is_active is not None:
        sets.append(f"is_active = ${idx}")
        params.append(body.is_active)
        idx += 1
    if body.password is not None:
        sets.append(f"hashed_password = ${idx}")
        params.append(hash_password(body.password))
        idx += 1

    if not sets:
        raise HTTPException(status_code=400, detail="No fields to update")

    sets.append("updated_at = NOW()")
    params.append(uid)

    await conn.execute(
        f"UPDATE users SET {', '.join(sets)} WHERE id = ${idx}",
        *params,
    )

    updated = await conn.fetchrow(
        """
        SELECT id::text AS id, username, role, is_active,
               created_at, updated_at
        FROM users WHERE id = $1
        """,
        uid,
    )
    return {
        "id": updated["id"],
        "username": updated["username"],
        "role": updated["role"],
        "is_active": updated["is_active"],
        "created_at": updated["created_at"].isoformat() if updated["created_at"] else None,
        "updated_at": updated["updated_at"].isoformat() if updated["updated_at"] else None,
    }


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    conn: asyncpg.Connection = Depends(get_conn),
    admin: dict = Depends(require_admin),
):
    """Delete a user account.  Requires the *admin* role."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user id")

    target = await conn.fetchrow(
        "SELECT username, role FROM users WHERE id = $1", uid,
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from deleting themselves
    if target["username"] == admin.get("username"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    # Prevent deleting the last admin
    if target["role"] == "admin":
        active_admins = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = true",
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last active admin",
            )

    await conn.execute("DELETE FROM users WHERE id = $1", uid)
    return None
