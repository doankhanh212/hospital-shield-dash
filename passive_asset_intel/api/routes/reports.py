"""Report endpoints — GET /api/reports/html and /api/reports/subnets.

Streams a self-contained HTML report (CVSS-based) that the frontend can open
in a new tab or save to disk.  See ``passive_asset_intel.reports.report_generator``
for the report body.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from passive_asset_intel.api.deps import get_config, get_conn
from passive_asset_intel.auth.deps import require_analyst
from passive_asset_intel.reports.report_generator import generate_html_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _parse_and_validate_subnets(raw: str, allowed: list[str]) -> list[str]:
    """Validate user-supplied CIDRs and restrict them to the configured scope.

    Every requested CIDR must be a valid network AND must be a subnet of (or
    equal to) one of the ``LOCAL_SUBNETS`` configured on the server.  This
    prevents a caller from dumping arbitrary ranges outside their scope.
    """
    try:
        allowed_nets = [ipaddress.ip_network(a, strict=False) for a in allowed]
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Invalid server config: {e}")

    out: list[str] = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {part}")

        if not any(net.subnet_of(a) for a in allowed_nets if a.version == net.version):
            raise HTTPException(
                status_code=400,
                detail=f"{part} is outside configured LOCAL_SUBNETS",
            )
        out.append(str(net))

    if not out:
        raise HTTPException(status_code=400, detail="At least one subnet is required")
    return out


@router.get("/subnets")
async def list_report_subnets(
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """Return the subnets a caller can pick from, with asset counts per CIDR.

    The UI uses this to populate the "choose subnets" picker before generating
    a report — counts let the user estimate report size.
    """
    subnets = config.local_subnets_list
    rows = await conn.fetch(
        """
        SELECT cidr::text AS cidr, COUNT(*)::int AS node_count
        FROM (
            SELECT
                unnest($1::inet[])   AS cidr,
                a.id                 AS asset_id,
                ai.ip_address        AS ip
            FROM assets a
            JOIN asset_ips ai
              ON ai.asset_id = a.id
             AND ai.is_primary = true
        ) x
        WHERE x.ip <<= x.cidr
        GROUP BY cidr
        """,
        subnets,
    )
    counts = {r["cidr"]: int(r["node_count"]) for r in rows}
    return {
        "subnets": [
            {"cidr": s, "node_count": counts.get(s, 0)}
            for s in subnets
        ]
    }


@router.get("/html", response_class=HTMLResponse)
async def get_html_report(
    download: bool = False,
    subnets: Optional[str] = Query(
        default=None,
        description="Comma-separated CIDRs. Defaults to all LOCAL_SUBNETS.",
    ),
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
    _user: dict = Depends(require_analyst),
):
    """Render a CVSS-based HTML report.

    Query params:
        download: if true, adds a ``Content-Disposition: attachment`` header
                  so the browser saves the file instead of rendering inline.
        subnets:  optional comma-separated CIDR list.  Every CIDR must be a
                  subnet of the server's configured LOCAL_SUBNETS.  When
                  omitted, the report covers the full configured scope.
    """
    allowed = config.local_subnets_list
    if subnets:
        scope = _parse_and_validate_subnets(subnets, allowed)
    else:
        scope = allowed

    try:
        html_str = await generate_html_report(conn, scope)
    except asyncpg.PostgresError as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "type": "database"})

    headers: dict[str, str] = {}
    if download:
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        headers["Content-Disposition"] = (
            f'attachment; filename="hospital-shield-report-{stamp}.html"'
        )
    return Response(content=html_str, media_type="text/html; charset=utf-8", headers=headers)
