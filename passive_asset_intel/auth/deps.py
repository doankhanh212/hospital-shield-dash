"""FastAPI authentication & authorization dependencies.

Usage in route functions::

    from passive_asset_intel.auth.deps import require_admin, require_analyst

    @router.get("/sensitive")
    async def endpoint(user=Depends(require_analyst)):
        ...
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from passive_asset_intel.auth.jwt_handler import decode_token

# Points at the login endpoint so Swagger UI can auto-fill the token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Decode the Bearer JWT and return ``{"username": …, "role": …}``.

    Raises HTTP 401 if the token is missing, expired, or invalid.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        if not username or not role:
            raise credentials_exc
        return {"username": username, "role": role}
    except JWTError:
        raise credentials_exc


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Raise HTTP 403 unless the authenticated user has the *admin* role."""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required",
        )
    return current_user


def require_analyst(current_user: dict = Depends(get_current_user)) -> dict:
    """Raise HTTP 403 unless the user has *admin* or *analyst* role."""
    if current_user["role"] not in {"admin", "analyst"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst role required",
        )
    return current_user
