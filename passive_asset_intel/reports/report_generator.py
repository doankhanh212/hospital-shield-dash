"""CVSS-based HTML report generator.

Builds a self-contained HTML report from live database state.  No external
templates or CSS — everything is inlined so the file can be saved / emailed /
printed without a server.

Public entry points:
    severity_from_cvss(score)       — map a CVSS number to "critical|high|medium|low"
    generate_html_report(conn, *)   — build the full HTML string

Severity mapping (per CVSS v3.1 qualitative rating, with "none" folded into
"low" because the report's low bucket is meant to include benign items):

    score >= 9.0   -> critical
    score >= 7.0   -> high
    score >= 4.0   -> medium
    score <  4.0   -> low
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Iterable, Sequence

import asyncpg


# ── Severity helpers ─────────────────────────────────────────────────────────

_CONFIDENCE_CAP = 95  # Never imply > 95% — this is a passive inference system.


def severity_from_cvss(score: float | int | None) -> str:
    """Map a CVSS score to one of: critical, high, medium, low.

    A ``None`` or 0 score is treated as ``low`` — the caller is responsible
    for filtering out assets with no vulnerabilities before rendering.
    """
    s = float(score or 0)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


_SEVERITY_COLORS = {
    "critical": "#f43f5e",  # rose-500
    "high":     "#f97316",  # orange-500
    "medium":   "#eab308",  # yellow-500
    "low":      "#22c55e",  # green-500
}


def _cap_confidence(raw: float | int | None) -> int:
    """Clamp a 0-100 confidence to 0-95 and round to int."""
    if raw is None:
        return 0
    v = float(raw)
    if v <= 1.0:       # stored as 0.0-1.0
        v = v * 100
    return max(0, min(_CONFIDENCE_CAP, int(round(v))))


def _esc(value) -> str:
    """HTML-escape, treating None as em-dash."""
    if value is None or value == "":
        return "&mdash;"
    return html.escape(str(value))


# ── SQL helpers ──────────────────────────────────────────────────────────────

_ASSETS_SQL = """
    WITH best_ir AS (
        SELECT DISTINCT ON (asset_id)
            asset_id,
            device_type,
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
    ),
    port_agg AS (
        SELECT asset_id,
               COUNT(DISTINCT port)::int AS open_ports
        FROM behaviors
        WHERE port IS NOT NULL AND port > 0
        GROUP BY asset_id
    )
    SELECT
        a.id::text                                              AS id,
        host(ai.ip_address)::text                               AS ip,
        COALESCE(ir.device_type, 'Unknown')                     AS device_type,
        COALESCE(ir.confidence, a.confidence_score, 0)::float   AS confidence,
        COALESCE(v.vuln_count, 0)::int                          AS vuln_count,
        COALESCE(v.max_cvss, 0)::float                          AS max_cvss,
        COALESCE(p.open_ports, 0)::int                          AS open_ports
    FROM assets a
    JOIN asset_ips  ai ON ai.asset_id = a.id AND ai.is_primary = true
    LEFT JOIN best_ir  ir ON ir.asset_id = a.id
    LEFT JOIN vuln_agg v  ON v.asset_id  = a.id
    LEFT JOIN port_agg p  ON p.asset_id  = a.id
    WHERE ai.ip_address <<= ANY($1::inet[])
    ORDER BY COALESCE(v.max_cvss, 0) DESC NULLS LAST,
             COALESCE(v.vuln_count, 0) DESC,
             ai.ip_address
"""

_VULNS_SQL = """
    SELECT
        host(ai.ip_address)::text   AS ip,
        vv.cve_id                    AS cve_id,
        vv.cvss_score                AS cvss_score,
        vv.description               AS description
    FROM asset_vulnerabilities av
    JOIN vulnerabilities vv ON vv.id = av.vulnerability_id
    JOIN asset_ips ai
      ON ai.asset_id = av.asset_id
     AND ai.is_primary = true
    WHERE ai.ip_address <<= ANY($1::inet[])
    ORDER BY vv.cvss_score DESC NULLS LAST, host(ai.ip_address)
"""


async def _fetch_assets(conn: asyncpg.Connection, subnets: Sequence[str]) -> list[dict]:
    rows = await conn.fetch(_ASSETS_SQL, list(subnets))
    return [dict(r) for r in rows]


async def _fetch_vulns(conn: asyncpg.Connection, subnets: Sequence[str]) -> list[dict]:
    rows = await conn.fetch(_VULNS_SQL, list(subnets))
    return [dict(r) for r in rows]


# ── HTML fragments ───────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    color = _SEVERITY_COLORS.get(sev, "#64748b")
    return (
        f'<span class="sev" style="background:{color}22;color:{color};'
        f'border:1px solid {color}55">{sev.upper()}</span>'
    )


def _cvss_cell(score: float | int | None) -> str:
    v = float(score or 0)
    if v <= 0:
        return '<span class="muted">&mdash;</span>'
    sev = severity_from_cvss(v)
    color = _SEVERITY_COLORS[sev]
    return (
        f'<span class="cvss" style="color:{color}">{v:.1f} '
        f'<span class="cvss-sev">({sev.title()})</span></span>'
    )


def _summary_section(
    total_assets: int,
    by_device: dict[str, int],
    cve_dist: dict[str, int],
) -> str:
    device_rows = "".join(
        f'<tr><td>{_esc(dt)}</td><td class="num">{cnt}</td></tr>'
        for dt, cnt in sorted(by_device.items(), key=lambda x: (-x[1], x[0]))
    ) or '<tr><td colspan="2" class="muted">Khong co du lieu</td></tr>'

    def sev_cell(sev: str) -> str:
        color = _SEVERITY_COLORS[sev]
        return (
            f'<div class="sev-box" style="border-color:{color}55;background:{color}15">'
            f'<div class="sev-label" style="color:{color}">{sev.upper()}</div>'
            f'<div class="sev-count">{cve_dist.get(sev, 0)}</div>'
            f'</div>'
        )

    return f"""
    <section>
      <h2>2. Tong quan</h2>
      <div class="summary-grid">
        <div class="card">
          <div class="big-num">{total_assets}</div>
          <div class="label">Tong so thiet bi</div>
        </div>
        <div class="card">
          <div class="label" style="margin-bottom:8px">Phan bo loai thiet bi</div>
          <table class="mini">
            <thead><tr><th>Loai</th><th class="num">So luong</th></tr></thead>
            <tbody>{device_rows}</tbody>
          </table>
        </div>
      </div>
      <div class="label" style="margin-top:16px;margin-bottom:8px">Phan bo CVE theo muc do</div>
      <div class="sev-grid">
        {sev_cell('critical')}
        {sev_cell('high')}
        {sev_cell('medium')}
        {sev_cell('low')}
      </div>
    </section>
    """


def _inventory_table(assets: Iterable[dict]) -> str:
    body_rows: list[str] = []
    for a in assets:
        max_cvss = float(a.get("max_cvss") or 0)
        sev = severity_from_cvss(max_cvss) if max_cvss > 0 else None
        conf = _cap_confidence(a.get("confidence"))
        body_rows.append(
            "<tr>"
            f"<td class=\"mono\">{_esc(a.get('ip'))}</td>"
            f"<td>{_esc(a.get('device_type') or 'Unknown')}</td>"
            f"<td class=\"num\">{conf}%</td>"
            f"<td class=\"num\">{_cvss_cell(max_cvss)}</td>"
            f"<td>{_severity_badge(sev) if sev else '<span class=\"muted\">&mdash;</span>'}</td>"
            f"<td class=\"num\">{int(a.get('open_ports') or 0)}</td>"
            "</tr>"
        )

    if not body_rows:
        body_rows.append('<tr><td colspan="6" class="muted">Khong co thiet bi trong pham vi</td></tr>')

    return f"""
    <section>
      <h2>3. Danh muc thiet bi</h2>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>Loai thiet bi</th>
            <th class="num">Tin cay (uoc tinh, max {_CONFIDENCE_CAP}%)</th>
            <th class="num">CVSS toi da</th>
            <th>Muc do</th>
            <th class="num">Cong mo</th>
          </tr>
        </thead>
        <tbody>{''.join(body_rows)}</tbody>
      </table>
    </section>
    """


def _vuln_table(vulns: Iterable[dict]) -> str:
    body_rows: list[str] = []
    for v in vulns:
        score = v.get("cvss_score")
        sev = severity_from_cvss(score) if score is not None else "low"
        desc = v.get("description") or ""
        if len(desc) > 240:
            desc = desc[:237] + "..."
        body_rows.append(
            "<tr>"
            f"<td class=\"mono\">{_esc(v.get('ip'))}</td>"
            f"<td class=\"mono\">{_esc(v.get('cve_id'))}</td>"
            f"<td class=\"num\">{_cvss_cell(score)}</td>"
            f"<td>{_severity_badge(sev)}</td>"
            f"<td class=\"desc\">{_esc(desc)}</td>"
            "</tr>"
        )

    if not body_rows:
        body_rows.append(
            '<tr><td colspan="5" class="muted empty">'
            'Khong co CVE nao trong pham vi bao cao. Kiem tra cau hinh NVD API key va dong bo.'
            '</td></tr>'
        )

    return f"""
    <section>
      <h2>4. Danh muc lo hong (CVE)</h2>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>CVE ID</th>
            <th class="num">CVSS</th>
            <th>Muc do</th>
            <th>Mo ta</th>
          </tr>
        </thead>
        <tbody>{''.join(body_rows)}</tbody>
      </table>
    </section>
    """


_NOTES_HTML = """
<section>
  <h2>5. Ghi chu phuong phap</h2>
  <ul class="notes">
    <li><b>Passive inference</b> — Tat ca du lieu loai thiet bi duoc suy luan
        tu luu luong mang (Zeek) bang dau van tay thu dong (JA3/JA3S, DHCP
        vendor, User-Agent, hanh vi port/protocol). Khong co thu nghiem chu
        dong, khong gui goi tin toi thiet bi.</li>
    <li><b>Confidence la uoc tinh</b> — Con so "Tin cay (est.)" la xac suat
        do model gan nhan. He thong gioi han toi da 95% de tranh ngu y chac
        chan tuyet doi; phan loai chi co gia tri tham chieu, khong phai su
        that mat dat.</li>
    <li><b>CVSS la chuan cong nghiep</b> — Diem va muc do lo hong theo
        CVSS v3.1 tu NVD. Muc do trong bao cao duoc tinh lai tu diem CVSS,
        khong dung mo hinh rui ro tuy bien nao.</li>
    <li><b>Pham vi</b> — Bao cao chi lay thiet bi co IP chinh nam trong
        <code>LOCAL_SUBNETS</code>; cac flow ra Internet khong thuoc pham vi.</li>
  </ul>
</section>
"""


_STYLE = """
  :root {
    --bg:       #0b1220;
    --panel:    #111a2e;
    --border:   #1f2a44;
    --text:     #e2e8f0;
    --muted:    #94a3b8;
    --accent:   #3b82f6;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px; line-height: 1.5;
  }
  .wrap { max-width: 1200px; margin: 0 auto; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  h2 { margin: 32px 0 14px; font-size: 15px; color: var(--text);
       padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  .meta { color: var(--muted); font-size: 12px; margin-bottom: 8px; }
  section { background: var(--panel); border: 1px solid var(--border);
            border-radius: 10px; padding: 20px 22px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  table.mini { font-size: 12px; }
  th, td { padding: 8px 10px; border-bottom: 1px solid var(--border);
           text-align: left; vertical-align: top; }
  th { color: var(--muted); font-weight: 600; text-transform: uppercase;
       font-size: 10.5px; letter-spacing: 0.04em; }
  td.mono, th.mono { font-family: "SF Mono", Menlo, Consolas, monospace; }
  td.num, th.num { text-align: right; }
  td.desc { color: var(--muted); max-width: 480px; }
  .muted { color: var(--muted); }
  .empty { text-align: center; padding: 20px !important; }
  tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: rgba(255,255,255,0.02); }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 10.5px; font-weight: 700; letter-spacing: 0.04em; }
  .cvss { font-family: "SF Mono", Menlo, Consolas, monospace; font-weight: 600; }
  .cvss-sev { font-weight: 400; opacity: 0.75; font-size: 11px; }
  .summary-grid { display: grid; grid-template-columns: 220px 1fr; gap: 16px; }
  .card { background: rgba(255,255,255,0.02); border: 1px solid var(--border);
          border-radius: 8px; padding: 16px; }
  .big-num { font-size: 32px; font-weight: 700; line-height: 1; color: var(--accent); }
  .label { color: var(--muted); font-size: 11.5px; text-transform: uppercase;
           letter-spacing: 0.05em; font-weight: 600; margin-top: 8px; }
  .sev-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
  .sev-box { border: 1px solid; border-radius: 8px; padding: 14px 16px; }
  .sev-label { font-size: 11px; font-weight: 700; letter-spacing: 0.05em; }
  .sev-count { font-size: 26px; font-weight: 700; margin-top: 4px; color: var(--text); }
  ul.notes { margin: 0; padding-left: 18px; }
  ul.notes li { margin: 6px 0; color: var(--muted); }
  ul.notes b { color: var(--text); }
  code { background: rgba(255,255,255,0.05); padding: 1px 5px;
         border-radius: 3px; font-family: "SF Mono", Menlo, Consolas, monospace;
         font-size: 11.5px; color: var(--text); }
  @media print {
    body { background: white; color: #000; }
    section { background: white; border: 1px solid #ccc; }
    h2 { border-color: #ccc; }
    .muted { color: #666; }
    tr:hover { background: transparent !important; }
  }
"""


# ── Public entry point ───────────────────────────────────────────────────────

async def generate_html_report(
    conn: asyncpg.Connection,
    subnets: Sequence[str],
    title: str = "Hospital Shield — Bao cao tai san va lo hong",
) -> str:
    """Build a self-contained HTML report string.

    Args:
        conn:    asyncpg connection (the caller manages lifecycle)
        subnets: list of CIDR strings, e.g. ``config.local_subnets_list``
        title:   report title (appears in the HEADER section and <title>)

    Returns:
        A single HTML document as a string.  Saves cleanly to disk and opens
        in any browser with no external requests.
    """
    assets = await _fetch_assets(conn, subnets)
    vulns = await _fetch_vulns(conn, subnets)

    total_assets = len(assets)
    by_device: dict[str, int] = {}
    for a in assets:
        dt = a.get("device_type") or "Unknown"
        by_device[dt] = by_device.get(dt, 0) + 1

    cve_dist: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        cve_dist[severity_from_cvss(v.get("cvss_score"))] += 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>{_STYLE}</style>
</head>
<body>
  <div class="wrap">
    <section>
      <h1>{html.escape(title)}</h1>
      <div class="meta">Tao luc: {generated_at}</div>
      <div class="meta">Pham vi: {html.escape(', '.join(subnets)) or 'Khong cau hinh'}</div>
    </section>

    {_summary_section(total_assets, by_device, cve_dist)}
    {_inventory_table(assets)}
    {_vuln_table(vulns)}
    {_NOTES_HTML}
  </div>
</body>
</html>"""
