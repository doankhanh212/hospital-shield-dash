/**
 * Admin → Data Management.
 *
 * - Shows live counts of every dataset
 * - Lets the operator toggle / configure auto-purge retention
 * - Provides 4 quick-clean actions (multicast, link-local, external, all)
 *   with mandatory dry-run preview before any destructive action
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle, Database, Globe2, Loader2, Network, Radio, Shield,
  Trash2,
} from 'lucide-react';
import { toast } from 'sonner';

import PageHeader from '@/components/widgets/PageHeader';
import { authStorage } from '@/lib/auth';

const API_BASE = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') || '/api';

// ── Types ─────────────────────────────────────────────────────────────────

interface DataStats {
  total_assets: number;
  total_ips: number;
  connections: number;
  dns_queries: number;
  tls_sessions: number;
  http_sessions: number;
  xdr_anomalies: number;
  xdr_incidents: number;
  xdr_audit_log: number;
  internal_ips: number;
  external_ips: number;
  multicast_ips: number;
  link_local_ips: number;
  ipv6_ips: number;
}

interface Retention {
  auto_purge_enabled: boolean;
  retention_days:     number;
  description:        string;
}

interface PurgeFilters {
  only_external?:        boolean;
  only_multicast?:       boolean;
  only_ipv6_link_local?: boolean;
  only_ipv6?:            boolean;
  older_than_days?:      number;
  subnet?:               string;
  delete_all?:           boolean;
  dry_run:               boolean;
}

interface PurgePreview {
  dry_run: boolean;
  matched_assets: number;
  would_delete?: { assets: number; connections: number; dns_queries: number; tls_sessions: number; http_sessions: number };
  deleted?:      { assets: number; connections: number; dns_queries: number; tls_sessions: number; http_sessions: number };
}

// ── Fetch ─────────────────────────────────────────────────────────────────

function authHeaders(): HeadersInit {
  const token = authStorage.getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function callJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(init?.headers || {}) },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `${path} → ${res.status}`);
  }
  return res.json();
}

const dataApi = {
  stats:       () => callJson<DataStats>('/data/stats'),
  retention:   () => callJson<Retention>('/data/retention'),
  setRetention:(days: number) => callJson<Retention>('/data/retention', {
    method: 'PUT', body: JSON.stringify({ days }),
  }),
  purge:       (filters: PurgeFilters) => callJson<PurgePreview>('/data/purge', {
    method: 'POST', body: JSON.stringify(filters),
  }),
};

// ── UI bits ───────────────────────────────────────────────────────────────

function StatTile({ label, value, hint, tone = 'default' }: {
  label: string; value: number | string; hint?: string;
  tone?: 'default' | 'warning' | 'critical' | 'muted';
}) {
  const toneCls = {
    default:  'text-foreground',
    warning:  'text-warning',
    critical: 'text-critical',
    muted:    'text-muted-foreground',
  }[tone];
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={`mt-0.5 font-mono text-lg font-bold tabular-nums ${toneCls}`}>{value}</p>
      {hint && <p className="text-[10px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

// ── Confirm modal ─────────────────────────────────────────────────────────

function ConfirmDialog({
  open, title, preview, danger = false, requireText, onCancel, onConfirm, busy,
}: {
  open: boolean;
  title: string;
  preview: PurgePreview | null;
  danger?: boolean;
  requireText?: string;     // e.g. "DELETE" — type-to-confirm
  onCancel: () => void;
  onConfirm: () => void;
  busy: boolean;
}) {
  const [typed, setTyped] = useState('');
  if (!open) return null;
  const w = preview?.would_delete;
  const matched = preview?.matched_assets ?? 0;
  const canConfirm =
    !busy && matched > 0 && (!requireText || typed === requireText);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-background/60 backdrop-blur-sm" onClick={onCancel} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-card p-5 shadow-2xl">
          <div className="flex items-start gap-3">
            <div className={`rounded-md p-2 ${danger ? 'bg-critical/15 text-critical' : 'bg-warning/15 text-warning'}`}>
              <AlertTriangle size={18} />
            </div>
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-semibold text-foreground">{title}</h3>
              <p className="mt-1 text-xs text-muted-foreground">
                {matched === 0
                  ? 'Không có asset nào khớp bộ lọc — không có gì để xoá.'
                  : 'Hành động này không thể hoàn tác. Anomaly history (xdr_anomalies) được giữ lại với asset_uuid = NULL.'}
              </p>

              {matched > 0 && w && (
                <div className="mt-3 space-y-1 rounded-md border border-border bg-background/40 px-3 py-2 text-xs">
                  <div className="flex justify-between"><span className="text-muted-foreground">Assets</span> <span className="font-mono tabular-nums text-foreground">{w.assets.toLocaleString()}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Connections</span> <span className="font-mono tabular-nums text-foreground">{w.connections.toLocaleString()}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">DNS queries</span> <span className="font-mono tabular-nums text-foreground">{w.dns_queries.toLocaleString()}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">TLS sessions</span> <span className="font-mono tabular-nums text-foreground">{w.tls_sessions.toLocaleString()}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">HTTP sessions</span> <span className="font-mono tabular-nums text-foreground">{w.http_sessions.toLocaleString()}</span></div>
                </div>
              )}

              {requireText && matched > 0 && (
                <div className="mt-3">
                  <label className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Gõ "{requireText}" để xác nhận
                  </label>
                  <input
                    autoFocus
                    value={typed}
                    onChange={(e) => setTyped(e.target.value)}
                    className="mt-1 w-full rounded-md border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-critical"
                  />
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 flex justify-end gap-2">
            <button
              onClick={onCancel}
              disabled={busy}
              className="rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted/30 transition disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              disabled={!canConfirm}
              className={`inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-xs font-medium transition disabled:opacity-40 disabled:cursor-not-allowed ${
                danger
                  ? 'border border-critical/40 bg-critical/10 text-critical hover:bg-critical/20'
                  : 'border border-warning/40 bg-warning/10 text-warning hover:bg-warning/20'
              }`}
            >
              {busy ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
              Xoá {matched > 0 ? `${matched} asset${matched > 1 ? 's' : ''}` : ''}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────

const REFRESH_MS = 5_000;

const AdminDataPage = () => {
  const qc = useQueryClient();

  const statsQ     = useQuery({ queryKey: ['data', 'stats'],     queryFn: dataApi.stats,     refetchInterval: REFRESH_MS });
  const retentionQ = useQuery({ queryKey: ['data', 'retention'], queryFn: dataApi.retention });

  const stats     = statsQ.data;
  const retention = retentionQ.data;

  const [pendingFilters, setPendingFilters] = useState<PurgeFilters | null>(null);
  const [pendingTitle,   setPendingTitle]   = useState('');
  const [pendingDanger,  setPendingDanger]  = useState(false);
  const [pendingRequire, setPendingRequire] = useState<string | undefined>(undefined);

  const previewM = useMutation({
    mutationFn: (filters: PurgeFilters) => dataApi.purge({ ...filters, dry_run: true }),
  });
  const purgeM = useMutation({
    mutationFn: (filters: PurgeFilters) => dataApi.purge({ ...filters, dry_run: false }),
    onSuccess: (data) => {
      const d = data.deleted;
      toast.success(`Đã xoá ${d?.assets ?? 0} assets / ${d?.connections ?? 0} connections`);
      qc.invalidateQueries({ queryKey: ['data'] });
      qc.invalidateQueries({ queryKey: ['unified'] });
      qc.invalidateQueries({ queryKey: ['xdr'] });
      setPendingFilters(null);
    },
    onError: (err) => toast.error(`Xoá thất bại: ${(err as Error).message}`),
  });

  const setRetentionM = useMutation({
    mutationFn: dataApi.setRetention,
    onSuccess: () => {
      toast.success('Đã cập nhật retention');
      qc.invalidateQueries({ queryKey: ['data', 'retention'] });
    },
    onError: (err) => toast.error((err as Error).message),
  });

  const askConfirm = (
    title: string,
    filters: PurgeFilters,
    opts: { danger?: boolean; requireText?: string } = {},
  ) => {
    setPendingTitle(title);
    setPendingFilters(filters);
    setPendingDanger(!!opts.danger);
    setPendingRequire(opts.requireText);
    previewM.mutate(filters);
  };

  const [retentionDraft, setRetentionDraft] = useState<number | null>(null);
  const draft = retentionDraft ?? retention?.retention_days ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quản lý dữ liệu"
        description="Tổng quan & dọn dẹp dữ liệu thủ công — không tự động xoá nếu retention = 0"
      />

      {/* Stats overview */}
      <section>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Tổng quan
        </h2>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
          <StatTile label="Assets"        value={stats?.total_assets ?? 0} />
          <StatTile label="IP addresses"  value={stats?.total_ips    ?? 0} hint={`${stats?.internal_ips ?? 0} internal · ${stats?.external_ips ?? 0} external`} />
          <StatTile label="Connections"   value={(stats?.connections ?? 0).toLocaleString()} />
          <StatTile label="DNS queries"   value={(stats?.dns_queries ?? 0).toLocaleString()} />
          <StatTile label="TLS sessions"  value={stats?.tls_sessions ?? 0} />
          <StatTile label="External IPs"  value={stats?.external_ips ?? 0} tone="warning" />
          <StatTile label="Multicast"     value={stats?.multicast_ips?? 0} tone="muted" />
          <StatTile label="IPv6 link-local" value={stats?.link_local_ips?? 0} tone="muted" />
          <StatTile label="XDR anomalies" value={stats?.xdr_anomalies?? 0} tone="critical" />
          <StatTile label="Audit log"     value={stats?.xdr_audit_log?? 0} />
        </div>
      </section>

      {/* Retention controls */}
      <section className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Auto-purge (retention)
            </h2>
            <p className="mt-1 text-sm text-foreground">
              {retention?.auto_purge_enabled
                ? <>Đang xoá tự động data cũ hơn <span className="font-mono text-warning">{retention.retention_days}</span> ngày</>
                : <>Auto-purge <span className="font-semibold text-success">đã tắt</span> — giữ toàn bộ dữ liệu</>}
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">{retention?.description}</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="number" min={0} max={3650}
              value={draft}
              onChange={(e) => setRetentionDraft(parseInt(e.target.value || '0', 10))}
              className="w-20 rounded-md border border-border bg-background px-2 py-1 text-sm text-right tabular-nums"
            />
            <span className="text-xs text-muted-foreground">ngày</span>
            <button
              onClick={() => setRetentionM.mutate(draft)}
              disabled={setRetentionM.isPending}
              className="inline-flex items-center gap-1 rounded-md border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary hover:bg-primary/20 disabled:opacity-50"
            >
              {setRetentionM.isPending ? <Loader2 size={12} className="animate-spin" /> : null}
              Lưu
            </button>
          </div>
        </div>
      </section>

      {/* Quick clean actions */}
      <section>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Quick clean
        </h2>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <QuickAction
            icon={<Globe2 size={16} />}
            tone="warning"
            title="Xoá tất cả IP external"
            sub={`${stats?.external_ips ?? 0} IPs — Google, Microsoft, Cloudflare…`}
            onClick={() => askConfirm('Xoá toàn bộ IP external', { only_external: true, dry_run: false })}
          />
          <QuickAction
            icon={<Radio size={16} />}
            tone="muted"
            title="Xoá multicast & link-local"
            sub={`${(stats?.multicast_ips ?? 0) + (stats?.link_local_ips ?? 0)} IPs — ff02::*, 224.x, fe80::*`}
            onClick={() => {
              askConfirm('Xoá multicast', { only_multicast: true, dry_run: false });
            }}
          />
          <QuickAction
            icon={<Network size={16} />}
            tone="muted"
            title="Xoá IPv6 link-local"
            sub={`${stats?.link_local_ips ?? 0} IPs — fe80::/10`}
            onClick={() => askConfirm('Xoá IPv6 link-local', { only_ipv6_link_local: true, dry_run: false })}
          />
          <QuickAction
            icon={<Shield size={16} />}
            tone="critical"
            title="Xoá toàn bộ assets + telemetry"
            sub="Reset network inventory — XDR audit history giữ lại"
            onClick={() => askConfirm(
              'Xoá toàn bộ assets',
              { delete_all: true, dry_run: false },
              { danger: true, requireText: 'DELETE' },
            )}
          />
        </div>
      </section>

      {/* Confirm dialog */}
      <ConfirmDialog
        open={!!pendingFilters}
        title={pendingTitle}
        preview={previewM.data ?? null}
        danger={pendingDanger}
        requireText={pendingRequire}
        busy={purgeM.isPending || previewM.isPending}
        onCancel={() => setPendingFilters(null)}
        onConfirm={() => pendingFilters && purgeM.mutate(pendingFilters)}
      />
    </div>
  );
};

function QuickAction({
  icon, title, sub, tone, onClick,
}: {
  icon: React.ReactNode; title: string; sub: string;
  tone: 'default' | 'warning' | 'critical' | 'muted';
  onClick: () => void;
}) {
  const toneCls = {
    default:  'border-border hover:border-primary/40',
    warning:  'border-warning/30 hover:border-warning/50',
    critical: 'border-critical/30 hover:border-critical/50',
    muted:    'border-border hover:border-muted-foreground/30',
  }[tone];
  const iconCls = {
    default:  'bg-primary/10 text-primary',
    warning:  'bg-warning/10 text-warning',
    critical: 'bg-critical/10 text-critical',
    muted:    'bg-muted/40 text-muted-foreground',
  }[tone];
  return (
    <button
      onClick={onClick}
      className={`flex items-start gap-3 rounded-lg border bg-card px-4 py-3 text-left transition ${toneCls}`}
    >
      <div className={`rounded-md p-2 ${iconCls}`}>{icon}</div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-foreground">{title}</p>
        <p className="text-[11px] text-muted-foreground">{sub}</p>
      </div>
      <Database size={14} className="text-muted-foreground/40" />
    </button>
  );
}

export default AdminDataPage;
