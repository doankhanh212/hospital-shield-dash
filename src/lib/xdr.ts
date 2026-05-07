/**
 * XDR API client — typed wrappers around /api/xdr/anomalies & /api/xdr/incidents.
 *
 * Auth: when XDR_DEV_OPEN=1 the backend ignores the Bearer token, so calls
 * succeed even from an unauthenticated session.  In production mode the
 * existing authStorage flow attaches the token automatically.
 */

import { authStorage } from './auth';

const API_BASE = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') || '/api';

// ── Types ────────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type AnomalyType =
  | 'port_scan'
  | 'dns_spike'
  | 'data_exfiltration'
  | 'rare_ja3'
  | 'rare_domain'
  | 'rogue_device';

export interface AnomalyEvidence {
  unique_ports?: number;
  unique_domains?: number;
  bytes_out?: number;
  bytes_out_mb?: number;
  conn_count?: number;
  dns_count?: number;
  threshold?: number;
  baseline_ports?: number;
  baseline_domains?: number;
  baseline_bytes?: number;
  deviation?: number;
  vt_malicious?: number;
  vt_suspicious?: number;
  abuse_score?: number;
  baseline_warm?: boolean;
  rare_ja3_count?: number;
  rare_ja3_sample?: string[];
  rare_domain_count?: number;
  rare_domain_sample?: string[];
  [k: string]: unknown;
}

export interface XdrAssetRef {
  uuid: string | null;
  ip:   string | null;
  mac:  string | null;
  vendor: string | null;
  device_type: string | null;
  confidence: number | null;
}

export type TriageStatus =
  | 'new' | 'investigating' | 'escalated' | 'resolved' | 'false_positive';

export interface XdrAnomaly {
  id: string;
  asset_id: string;
  asset_uuid: string | null;
  type: AnomalyType;
  severity: Severity;
  score: number;
  description: string;
  evidence: AnomalyEvidence;
  first_seen: string;
  last_seen: string;
  count: number;
  asset: XdrAssetRef | null;
  // Triage fields (added by upgrade)
  status: TriageStatus;
  assigned_to: string | null;
  note: string | null;
  updated_at: string | null;
}

export interface AuditEvent {
  id: string;
  entity_type: 'anomaly' | 'incident';
  entity_id: string;
  action: 'assign' | 'status_change' | 'note' | 'escalate' | string;
  old_value: Record<string, unknown> | null;
  new_value: Record<string, unknown> | null;
  actor: string | null;
  created_at: string;
}

export interface TimelineEvent {
  time: string;
  type: 'anomaly' | 'action';
  description: string;
  details: Record<string, unknown>;
}

export interface XdrIncident {
  id: string;
  asset_id: string;
  asset_uuid: string | null;
  severity: Severity;
  anomaly_types: AnomalyType[];
  first_seen: string;
  last_seen: string;
  asset: XdrAssetRef | null;
}

export interface Paginated<T> {
  items: T[];
  total: number;
}

// ── Fetch helpers ────────────────────────────────────────────────────────────

function authHeaders(): HeadersInit {
  const token = authStorage.getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function buildUrl(path: string, params?: Record<string, string | number | undefined>): string {
  const url = new URL(`${API_BASE}${path}`, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v === undefined || v === null || v === '') return;
      url.searchParams.set(k, String(v));
    });
  }
  return url.toString();
}

async function getXdr<T>(
  path: string,
  params?: Record<string, string | number | undefined>,
): Promise<T> {
  const res = await fetch(buildUrl(path, params), { headers: authHeaders() });
  // /api/xdr/* is dev-open server-side; never bounce to /login on 401 here
  if (!res.ok) throw new Error(`XDR API ${path} → ${res.status}`);
  return res.json();
}

// ── Endpoints ────────────────────────────────────────────────────────────────

export interface AnomalyQuery {
  asset_id?: string;
  severity?: Severity;
  type?: AnomalyType;
  limit?:  number;
  offset?: number;
}

async function sendXdr<T>(method: 'POST' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<T> {
  const res = await fetch(buildUrl(path), {
    method,
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `XDR ${method} ${path} → ${res.status}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : ({} as T);
}

export const xdrApi = {
  listAnomalies: (q: AnomalyQuery = {}) =>
    getXdr<Paginated<XdrAnomaly>>('/xdr/anomalies', {
      asset_id: q.asset_id,
      severity: q.severity,
      type:     q.type,
      limit:    q.limit  ?? 100,
      offset:   q.offset ?? 0,
    }),

  listIncidents: (q: { asset_id?: string; severity?: Severity; limit?: number; offset?: number } = {}) =>
    getXdr<Paginated<XdrIncident>>('/xdr/incidents', {
      asset_id: q.asset_id,
      severity: q.severity,
      limit:    q.limit  ?? 50,
      offset:   q.offset ?? 0,
    }),

  // ── Triage actions ──────────────────────────────────────────────────────
  setStatus: (anomalyId: string, status: TriageStatus) =>
    sendXdr<XdrAnomaly>('PATCH', `/xdr/anomalies/${anomalyId}/status`, { status }),

  assign: (anomalyId: string, user: string | null) =>
    sendXdr<XdrAnomaly>('POST', `/xdr/anomalies/${anomalyId}/assign`, { user }),

  addNote: (anomalyId: string, note: string) =>
    sendXdr<XdrAnomaly>('POST', `/xdr/anomalies/${anomalyId}/note`, { note }),

  // ── Audit + timeline ───────────────────────────────────────────────────
  audit: (q: { entity_id?: string; asset_id?: string; limit?: number } = {}) =>
    getXdr<Paginated<AuditEvent>>('/xdr/audit', {
      entity_id: q.entity_id,
      asset_id:  q.asset_id,
      limit:     q.limit ?? 200,
    }),

  timeline: (assetId: string, limit = 100) =>
    getXdr<Paginated<TimelineEvent>>(`/xdr/assets/${assetId}/timeline`, { limit }),
};

// ── Severity helpers ─────────────────────────────────────────────────────────

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

export const SEVERITY_TW: Record<Severity, { bg: string; text: string; border: string; ring: string; bar: string }> = {
  critical: { bg: 'bg-critical/15', text: 'text-critical', border: 'border-critical/30', ring: 'ring-critical/40', bar: 'bg-critical' },
  high:     { bg: 'bg-high/15',     text: 'text-high',     border: 'border-high/30',     ring: 'ring-high/40',     bar: 'bg-high' },
  medium:   { bg: 'bg-medium/15',   text: 'text-medium',   border: 'border-medium/30',   ring: 'ring-medium/40',   bar: 'bg-medium' },
  low:      { bg: 'bg-low/15',      text: 'text-low',      border: 'border-low/30',      ring: 'ring-low/40',      bar: 'bg-low' },
};

export function fmtType(t: AnomalyType): string {
  return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function fmtBytes(n: number | undefined): string {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3)   return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export function fmtRelativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return '—';
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60)    return `${Math.max(1, Math.round(diff))}s ago`;
  if (diff < 3600)  return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

export const STATUS_TONE: Record<TriageStatus, { label: string; cls: string }> = {
  new:            { label: 'New',          cls: 'bg-low/15 text-low border-low/30' },
  investigating:  { label: 'Investigating',cls: 'bg-medium/15 text-medium border-medium/30' },
  escalated:      { label: 'Escalated',    cls: 'bg-high/15 text-high border-high/30' },
  resolved:       { label: 'Resolved',     cls: 'bg-success/15 text-success border-success/30' },
  false_positive: { label: 'False positive',cls: 'bg-muted text-muted-foreground border-border' },
};

export function intelTag(ev: AnomalyEvidence): { label: 'malicious' | 'suspicious' | 'clean' | 'unknown'; tone: Severity } {
  const vtMal  = ev.vt_malicious  ?? 0;
  const vtSusp = ev.vt_suspicious ?? 0;
  const abuse  = ev.abuse_score   ?? 0;
  if (vtMal >= 5 || abuse >= 75)            return { label: 'malicious',  tone: 'critical' };
  if (vtMal >= 1 || vtSusp >= 3 || abuse >= 25) return { label: 'suspicious', tone: 'high' };
  if (vtMal === 0 && vtSusp === 0 && abuse === 0) {
    // No signal — could be unenriched (no key) or genuinely clean.
    return { label: 'unknown', tone: 'low' };
  }
  return { label: 'clean', tone: 'low' };
}
