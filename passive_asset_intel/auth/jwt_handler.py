"""JWT creation and verification using python-jose + passlib/bcrypt.

Environment variable required:
    JWT_SECRET_KEY  — at least 32 random characters.
                      Generate with: python -c "import secrets; print(secrets.token_hex(32))"
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from passive_asset_intel.utils.config import load_config

_ALGORITHM = "HS256"
_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _secret_key() -> str:
    """Return the JWT secret key, raising if it is missing or too short."""
    key = load_config().jwt_secret_key
    if not key or len(key) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY must be set in .env and be at least 32 characters. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return key


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    return pwd_context.verify(plain, hashed)


def create_access_token(
    data: dict[str, Any],
    *,
    expires_minutes: int = _ACCESS_TOKEN_EXPIRE_MINUTES,
) -> str:
    """Encode a signed JWT with the given claims.

    Args:
        data:            Claims to include (``sub``, ``role``, …).
        expires_minutes: Token lifetime in minutes.

    Returns:
        A signed JWT string.
    """
    payload = data.copy()
    payload.update(
        {
            "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),  # unique token ID — supports future revocation
        }
    )
    return jwt.encode(payload, _secret_key(), algorithm=_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify *token*.

    Raises:
        jose.JWTError: Token is invalid, expired, or tampered with.
    """
    return jwt.decode(token, _secret_key(), algorithms=[_ALGORITHM])
