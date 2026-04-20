"""Topology endpoint — GET /api/topology.

Returns a VLAN-grouped view of the local network with the nodes (assets)
and the aggregated flow edges between them.  Used by the frontend to draw
an SVG network diagram.

Response shape::

    {
      "vlans": [
        {
          "id": "103.98.152.0/24",
          "name": "103.98.152.0/24",
          "cidr": "103.98.152.0/24",
          "node_count": 12,
          "nodes": [
            {
              "id": "<uuid>",
              "ip": "103.98.152.17",
              "hostname": "mri-01",
              "device_type": "IoMT",
              "vendor": "GE Healthcare",
              "status": "online"
            }, ...
          ]
        }, ...
      ],
      "connections": [
        {
          "src_id": "<uuid>",
          "dst_id": "<uuid>",
          "protocol": "tcp",
          "service": "https",
          "count": 42,
          "bytes": 183422
        }, ...
      ],
      "stats": {
        "total_vlans": 3,
        "total_nodes": 87,
        "total_connections": 412
      }
    }
"""

from __future__ import annotations

import ipaddress
from typing import Sequence

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from passive_asset_intel.api.deps import get_config, get_conn

router = APIRouter(prefix="/api", tags=["topology"])


# ── VLAN buckets ─────────────────────────────────────────────
def _parse_subnets(cidrs: Sequence[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a list of CIDR strings into ip_network objects, sorted most-specific first."""
    parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            parsed.append(ipaddress.ip_network(c, strict=False))
        except (ValueError, TypeError):
            continue
    # Sort by prefix length descending so /24 wins over /8 when an IP matches both
    parsed.sort(key=lambda n: n.prefixlen, reverse=True)
    return parsed


def _vlan_for_ip(
    ip_str: str,
    local_networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str:
    """Return the VLAN CIDR bucket an IP belongs to.

    Strategy:
    1. If the IP matches one of the configured LOCAL_SUBNETS, use that exact
       CIDR as the VLAN ID.  This keeps VPS ranges (e.g. 103.98.152.0/24) as
       their own lane instead of getting collapsed into a /16.
    2. Otherwise fall back to the /16 (IPv4) or /64 (IPv6) that contains the IP.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return "unknown"

    for net in local_networks:
        if ip in net:
            return str(net)

    if isinstance(ip, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/16", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


@router.get("/topology")
async def get_topology(
    conn: asyncpg.Connection = Depends(get_conn),
    config=Depends(get_config),
):
    """Return the network topology as VLAN-grouped nodes plus aggregated edges.

    Only includes assets whose primary IP falls within LOCAL_SUBNETS.  Edges
    are aggregated over the full connections table so the diagram reflects
    all observed traffic, not just the last few minutes.
    """
    try:
        subnets = config.local_subnets_list
        local_networks = _parse_subnets(subnets)

        # ── Fetch nodes (local assets only) ──────────────────
        # Use DISTINCT ON to pick a single inference_results row per asset
        # (some assets have duplicate rows with NULL confidence — we want
        # the row with the highest non-null confidence).
        node_rows = await conn.fetch(
            """
            WITH best_ir AS (
                SELECT DISTINCT ON (asset_id)
                    asset_id,
                    device_type,
                    behavior_type,
                    confidence
                FROM inference_results
                ORDER BY asset_id,
                         (confidence IS NULL) ASC,
                         confidence DESC NULLS LAST
            ),
            vuln_agg AS (
                SELECT av.asset_id,
                       COUNT(*)::int      AS vuln_count,
                       MAX(vv.cvss_score) AS max_cvss
                FROM asset_vulnerabilities av
                JOIN vulnerabilities vv ON vv.id = av.vulnerability_id
                GROUP BY av.asset_id
            )
            SELECT
                a.id::text                                         AS id,
                host(ai.ip_address)::text                          AS ip,
                ah.hostname                                        AS hostname,
                COALESCE(ir.device_type, 'Unknown')                AS device_type,
                ir.behavior_type                                   AS behavior_type,
                a.vendor                                           AS vendor,
                COALESCE(ir.confidence, a.confidence_score, 0)::float AS confidence,
                a.last_seen                                        AS last_seen,
                COALESCE(v.vuln_count, 0)::int                     AS vuln_count,
                COALESCE(v.max_cvss, 0)::float                     AS max_cvss,
                CASE
                    WHEN a.last_seen > NOW() - INTERVAL '5 minutes'
                    THEN 'online'
                    ELSE 'offline'
                END                                                AS status
            FROM assets a
            JOIN asset_ips ai
              ON ai.asset_id = a.id
             AND ai.is_primary = true
            LEFT JOIN asset_hostnames ah ON ah.asset_id = a.id
            LEFT JOIN best_ir         ir ON ir.asset_id = a.id
            LEFT JOIN vuln_agg        v  ON v.asset_id  = a.id
            WHERE ai.ip_address <<= ANY($1::inet[])
            ORDER BY ai.ip_address
            """,
            subnets,
        )

        # Build node lookup keyed by id; also keep allowed_ids set so
        # connections to non-local destinations get dropped cleanly.
        node_by_id: dict[str, dict] = {}
        allowed_ids: set[str] = set()
        for r in node_rows:
            nid = r["id"]
            node_by_id[nid] = {
                "id": nid,
                "ip": r["ip"],
                "hostname": r["hostname"],
                "device_type": r["device_type"],
                "behavior_type": r["behavior_type"],
                "vendor": r["vendor"],
                "confidence": float(r["confidence"]) if r["confidence"] is not None else None,
                "vuln_count": int(r["vuln_count"] or 0),
                "max_cvss": float(r["max_cvss"] or 0),
                "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
                "status": r["status"],
            }
            allowed_ids.add(nid)

        # ── Fetch aggregated connections (both endpoints must be local) ─
        edge_rows = await conn.fetch(
            """
            SELECT
                c.src_asset_id::text        AS src_id,
                c.dst_asset_id::text        AS dst_id,
                c.protocol                  AS protocol,
                c.service                   AS service,
                COUNT(*)::int               AS count,
                COALESCE(SUM(c.bytes_sent + c.bytes_received), 0)::bigint AS bytes
            FROM connections c
            WHERE c.src_asset_id IS NOT NULL
              AND c.dst_asset_id IS NOT NULL
              AND c.src_ip <<= ANY($1::inet[])
              AND c.dst_ip <<= ANY($1::inet[])
            GROUP BY c.src_asset_id, c.dst_asset_id, c.protocol, c.service
            ORDER BY count DESC
            LIMIT 500
            """,
            subnets,
        )

        connections: list[dict] = []
        for r in edge_rows:
            src = r["src_id"]
            dst = r["dst_id"]
            if src not in allowed_ids or dst not in allowed_ids:
                continue
            if src == dst:
                continue  # skip self-loops
            connections.append(
                {
                    "src_id": src,
                    "dst_id": dst,
                    "protocol": r["protocol"],
                    "service": r["service"],
                    "count": r["count"],
                    "bytes": int(r["bytes"]) if r["bytes"] is not None else 0,
                }
            )

        # ── Bucket nodes into VLAN groups ────────────────────
        vlan_buckets: dict[str, list[dict]] = {}
        for node in node_by_id.values():
            ip = node["ip"]
            if not ip:
                continue
            vlan_id = _vlan_for_ip(ip, local_networks)
            vlan_buckets.setdefault(vlan_id, []).append(node)

        vlans = []
        for vlan_id in sorted(vlan_buckets.keys()):
            nodes = vlan_buckets[vlan_id]
            # Stable ordering inside each VLAN
            nodes.sort(key=lambda n: (n["device_type"] or "", n["ip"] or ""))
            vlans.append(
                {
                    "id": vlan_id,
                    "name": vlan_id,
                    "cidr": vlan_id,
                    "node_count": len(nodes),
                    "nodes": nodes,
                }
            )
        # Largest VLAN first so the diagram leads with the most informative box
        vlans.sort(key=lambda v: v["node_count"], reverse=True)

        return {
            "vlans": vlans,
            "connections": connections,
            "stats": {
                "total_vlans": len(vlans),
                "total_nodes": len(node_by_id),
                "total_connections": len(connections),
            },
        }

    except asyncpg.PostgresError as e:
        raise HTTPException(
            status_code=500, detail={"error": str(e), "type": "database"}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail={"error": str(e), "type": "internal"}
        )
