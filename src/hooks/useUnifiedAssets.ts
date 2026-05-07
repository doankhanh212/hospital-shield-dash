/**
 * Unified asset / activity layer — exposes a single hook the dashboard can
 * use without knowing which pipeline (legacy or XDR) populated the data.
 *
 * Rule: legacy is the source of truth for assets & topology.  XDR is the
 *       enrichment layer (anomalies, severity overlay).  When legacy is
 *       empty (fresh install / pipeline not yet running), we silently fall
 *       back to xdr_assets so no page is ever blank.
 */

import { useQuery } from '@tanstack/react-query';

import { authStorage } from '@/lib/auth';
import { type Severity, SEVERITY_RANK, type XdrAnomaly } from '@/lib/xdr';
import { useAnomalies } from './useXdr';

const REFRESH_MS = 5_000;
const API_BASE = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') || '/api';

interface LegacyAssetSlim {
  id: string;
  ip: string | null;
  mac: string | null;
  vendor: string | null;
  deviceType: string | null;
  status: string;
  last_seen: string | null;
}

interface UnifiedAsset {
  id: string;             // UUID for legacy, IP for XDR-only
  ip: string;
  mac: string | null;
  vendor: string | null;
  device_type: string | null;
  last_seen: string | null;
  source: 'legacy' | 'xdr';
  severity: Severity | null;   // overlay from XDR
  alert_count: number;          // overlay from XDR
}

function authHeaders(): HeadersInit {
  const token = authStorage.getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function fetchLegacyAssets(): Promise<LegacyAssetSlim[]> {
  const res = await fetch(`${API_BASE}/assets?limit=500`, { headers: authHeaders() });
  if (!res.ok) {
    if (res.status === 401) return [];   // not logged in → treat as empty (XDR fallback kicks in)
    throw new Error(`assets API → ${res.status}`);
  }
  const data = await res.json();
  const items = (data?.items ?? data ?? []) as Array<Record<string, unknown>>;
  return items.map((a) => ({
    id:         (a.id as string) ?? '',
    ip:         (a.ip as string | null) ?? null,
    mac:        (a.mac as string | null) ?? null,
    vendor:     (a.vendor as string | null) ?? null,
    deviceType: (a.deviceType as string | null) ?? null,
    status:     (a.status as string) ?? 'offline',
    last_seen:  (a.last_seen as string | null) ?? null,
  }));
}

function highestSeverity(list: XdrAnomaly[]): Severity | null {
  if (list.length === 0) return null;
  let best: Severity = 'low'; let rank = 0;
  for (const a of list) {
    const r = SEVERITY_RANK[a.severity];
    if (r > rank) { rank = r; best = a.severity; }
  }
  return best;
}

/**
 * Returns a unified asset list.  Legacy first; if legacy is empty, the same
 * shape is synthesised from `xdr_assets` so the dashboard never goes blank.
 * XDR anomalies are always overlaid as `severity` + `alert_count` enrichment.
 */
export function useUnifiedAssets() {
  const legacyQ = useQuery({
    queryKey: ['unified', 'legacy-assets'],
    queryFn:  fetchLegacyAssets,
    refetchInterval: REFRESH_MS,
    refetchOnWindowFocus: false,
    placeholderData: (prev) => prev,
  });

  const anomQ = useAnomalies({ limit: 500 }, REFRESH_MS);

  const legacy = legacyQ.data ?? [];
  const anomalies = anomQ.data?.items ?? [];

  // Build per-IP enrichment from XDR
  const byIp = new Map<string, XdrAnomaly[]>();
  for (const a of anomalies) {
    if (!byIp.has(a.asset_id)) byIp.set(a.asset_id, []);
    byIp.get(a.asset_id)!.push(a);
  }

  let unified: UnifiedAsset[] = [];
  let source: 'legacy' | 'xdr' = 'legacy';

  if (legacy.length > 0) {
    unified = legacy.map(a => ({
      id:          a.id,
      ip:          a.ip ?? '',
      mac:         a.mac,
      vendor:      a.vendor,
      device_type: a.deviceType,
      last_seen:   a.last_seen,
      source:      'legacy',
      severity:    a.ip ? highestSeverity(byIp.get(a.ip) ?? []) : null,
      alert_count: a.ip ? (byIp.get(a.ip)?.length ?? 0) : 0,
    }));
  } else {
    // Fallback: synthesise asset list from XDR-known IPs
    source = 'xdr';
    const ips = Array.from(new Set(anomalies.map(a => a.asset_id)));
    unified = ips.map(ip => {
      const list = byIp.get(ip) ?? [];
      const first = list[0];
      return {
        id:          ip,
        ip,
        mac:         first?.asset?.mac ?? null,
        vendor:      first?.asset?.vendor ?? null,
        device_type: first?.asset?.device_type ?? null,
        last_seen:   list[0]?.last_seen ?? null,
        source:      'xdr',
        severity:    highestSeverity(list),
        alert_count: list.length,
      };
    });
  }

  return {
    items: unified,
    source,
    isLoading: legacyQ.isLoading && anomQ.isLoading && unified.length === 0,
    error:   legacyQ.error || anomQ.error,
  };
}
