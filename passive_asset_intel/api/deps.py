"""FastAPI dependencies — asyncpg pool and connection injection."""

from __future__ import annotations

from typing import AsyncGenerator

import asyncpg
from fastapi import Depends, Request


def get_config(request: Request):
    """Return the app config stored on app.state during lifespan."""
    return request.app.state.config


def get_pool(request: Request) -> asyncpg.Pool:
    """Return the asyncpg pool stored on app.state during lifespan.

    Args:
        request: The incoming FastAPI request (injected automatically).

    Returns:
        The shared asyncpg connection pool.
    """
    return request.app.state.pool


async def get_conn(
    pool: asyncpg.Pool = Depends(get_pool),
) -> AsyncGenerator[asyncpg.Connection, None]:
    """Acquire an asyncpg connection from the pool and release it on exit.

    Yields:
        An asyncpg Connection object.
    """
    async with pool.acquire() as conn:
        yield conn
