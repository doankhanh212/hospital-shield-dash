/**
 * SOC Control Panel — replaces the legacy "Quét mạng" card.
 *
 * Drives /api/soc/{status,start,stop,metrics}.  Auto-polls status + metrics
 * every 3s.  No page reloads.  Health badge:
 *   🟢 LIVE       (running + EPS > 0)
 *   ⚪ STOPPED    (not running)
 *   🔴 DEGRADED   (running but EPS == 0)
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity, Cpu, HardDrive, Loader2, Play, Radio, Square, Wifi,
} from 'lucide-react';
import { toast } from 'sonner';

import { authStorage } from '@/lib/auth';

const API_BASE = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') || '/api';
const REFRESH_MS = 3_000;

type SocStatus = 'running' | 'stopped';
type Health    = 'healthy' | 'degraded' | 'idle';

interface StatusPayload {
  status: SocStatus;
  pid:    number | null;
  uptime: number;
  job_id: string | null;
  started_at: string | null;
}

interface MetricsPayload {
  status: SocStatus;
  health: Health;
  cpu:    number;
  memory: number;
  events_per_sec: number;
  logs_ingested:  number;
  log_files:      number;
  last_log_time:  string | null;
  lag_seconds:    number | null;
  breakdown:      Record<string, number>;
  interface:      string;
  log_dir:        string;
}

// ── Fetchers ──────────────────────────────────────────────────────────────

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

const socApi = {
  status:  () => callJson<StatusPayload>('/soc/status'),
  metrics: () => callJson<MetricsPayload>('/soc/metrics'),
  start:   () => callJson<unknown>('/soc/start',  { method: 'POST' }),
  stop:    () => callJson<unknown>('/soc/stop',   { method: 'POST' }),
};

// ── Hooks ─────────────────────────────────────────────────────────────────

function useSocStatus()  { return useQuery({
  queryKey: ['soc', 'status'],
  queryFn:  socApi.status,
  refetchInterval: REFRESH_MS,
  refetchOnWindowFocus: false,
  retry: 0,
}); }

function useSocMetrics() { return useQuery({
  queryKey: ['soc', 'metrics'],
  queryFn:  socApi.metrics,
  refetchInterval: REFRESH_MS,
  refetchOnWindowFocus: false,
  retry: 0,
}); }

// ── Format helpers ────────────────────────────────────────────────────────

function fmtUptime(s: number): string {
  if (!s) return '—';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}g ${m}p`;
  if (m > 0) return `${m}p ${sec}s`;
  return `${sec}s`;
}

function fmtRel(iso: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const d = (Date.now() - t) / 1000;
  if (d < 60)   return `${Math.max(1, Math.round(d))} giây trước`;
  if (d < 3600) return `${Math.round(d / 60)} phút trước`;
  return `${Math.round(d / 3600)} giờ trước`;
}

// ── UI bits ───────────────────────────────────────────────────────────────

function HealthDot({ health, status }: { health: Health; status: SocStatus }) {
  if (status === 'stopped')  return <span className="inline-block h-2.5 w-2.5 rounded-full bg-muted-foreground" title="ĐÃ DỪNG" />;
  if (health === 'degraded') return <span className="inline-block h-2.5 w-2.5 rounded-full bg-critical animate-pulse" title="SUY GIẢM" />;
  return <span className="inline-block h-2.5 w-2.5 rounded-full bg-success animate-pulse" title="TRỰC TUYẾN" />;
}

function HealthLabel({ health, status }: { health: Health; status: SocStatus }) {
  if (status === 'stopped')  return <span className="font-semibold text-muted-foreground">ĐÃ DỪNG</span>;
  if (health === 'degraded') return <span className="font-semibold text-critical">SUY GIẢM</span>;
  return <span className="font-semibold text-success">TRỰC TUYẾN</span>;
}

function Metric({ icon: Icon, label, value, sub }: { icon: typeof Cpu; label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-md border border-border bg-background/40 px-2.5 py-1.5">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        <Icon size={11} /> {label}
      </div>
      <div className="mt-0.5 font-mono text-sm tabular-nums text-foreground">{value}</div>
      {sub && <div className="text-[10px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────

const SocControlPanel = () => {
  const qc       = useQueryClient();
  const statusQ  = useSocStatus();
  const metricsQ = useSocMetrics();

  const status: SocStatus = statusQ.data?.status   ?? 'stopped';
  const health: Health    = metricsQ.data?.health  ?? 'idle';
  const eps               = metricsQ.data?.events_per_sec ?? 0;

  const startM = useMutation({
    mutationFn: socApi.start,
    onSuccess:  () => {
      toast.success('Đã bắt đầu giám sát mạng');
      qc.invalidateQueries({ queryKey: ['soc'] });
    },
    onError:    (err) => toast.error(`Khởi động thất bại: ${(err as Error).message}`),
  });
  const stopM = useMutation({
    mutationFn: socApi.stop,
    onSuccess:  () => {
      toast.success('Đã dừng giám sát mạng');
      qc.invalidateQueries({ queryKey: ['soc'] });
    },
    onError:    (err) => toast.error(`Dừng thất bại: ${(err as Error).message}`),
  });

  const isRunning = status === 'running';
  const isBusy    = startM.isPending || stopM.isPending;
  const apiError  =
    (statusQ.error as Error | undefined)?.message ||
    (metricsQ.error as Error | undefined)?.message;

  const m = metricsQ.data;

  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <HealthDot health={health} status={status} />
          <div>
            <p className="text-xs font-semibold text-foreground">
              Giám sát mạng &nbsp;·&nbsp; <HealthLabel health={health} status={status} />
            </p>
            <p className="text-[11px] text-muted-foreground">
              {isRunning
                ? <>Cảm biến <code className="font-mono text-foreground">{m?.interface ?? 'wlp2s0'}</code> · thời gian chạy <span className="text-foreground">{fmtUptime(statusQ.data?.uptime ?? 0)}</span></>
                : 'Đang chờ — nhấn Bắt đầu để xử lý lưu lượng trực tiếp'}
            </p>
          </div>
        </div>

        <div className="flex gap-1.5">
          <button
            onClick={() => startM.mutate()}
            disabled={isRunning || isBusy}
            className="flex items-center gap-1.5 rounded-lg border border-success/30 bg-success/10 px-3 py-1.5 text-[11px] font-medium text-success transition hover:bg-success/20 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {startM.isPending ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
            Bắt đầu
          </button>
          <button
            onClick={() => stopM.mutate()}
            disabled={!isRunning || isBusy}
            className="flex items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-[11px] font-medium text-rose-400 transition hover:bg-rose-500/20 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {stopM.isPending ? <Loader2 size={12} className="animate-spin" /> : <Square size={12} />}
            Dừng
          </button>
        </div>
      </div>

      {/* API/connection error */}
      {apiError && (
        <div className="rounded-md border border-critical/30 bg-critical/10 px-2.5 py-1.5 text-[11px] text-critical">
          {apiError}
        </div>
      )}

      {/* Degraded warning */}
      {isRunning && health === 'degraded' && (
        <div className="rounded-md border border-critical/30 bg-critical/10 px-2.5 py-1.5 text-[11px] text-critical">
          ⚠ Không phát hiện lưu lượng đến — kiểm tra cảm biến Zeek đang bắt gói trên <code className="font-mono">{m?.interface ?? 'wlp2s0'}</code>.
        </div>
      )}

      {/* Metrics grid */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Metric
          icon={Cpu}
          label="CPU"
          value={`${(m?.cpu ?? 0).toFixed(1)}%`}
        />
        <Metric
          icon={HardDrive}
          label="Bộ nhớ"
          value={`${(m?.memory ?? 0).toFixed(1)}%`}
        />
        <Metric
          icon={Activity}
          label="Sự kiện / giây"
          value={eps.toFixed(2)}
          sub={isRunning ? (eps > 0 ? 'đang stream' : 'chưa có sự kiện') : 'tạm dừng'}
        />
        <Metric
          icon={Radio}
          label="Tệp nhật ký"
          value={String(m?.log_files ?? 0)}
          sub={m?.last_log_time ? `mới nhất ${fmtRel(m.last_log_time)}` : '—'}
        />
      </div>

      {/* Footer: breakdown + lag */}
      {m?.breakdown && Object.keys(m.breakdown).length > 0 && (
        <div className="flex flex-wrap items-center gap-2 border-t border-border/60 pt-2 text-[11px]">
          <Wifi size={11} className="text-muted-foreground" />
          {Object.entries(m.breakdown).map(([k, v]) => (
            <span key={k} className="rounded border border-border bg-background/60 px-1.5 py-0.5 text-muted-foreground">
              {k} <span className="font-mono tabular-nums text-foreground">{v.toLocaleString()}</span>
            </span>
          ))}
          {m.lag_seconds != null && (
            <span className="ml-auto text-muted-foreground">
              độ trễ thu nhận <span className="font-mono tabular-nums text-foreground">{m.lag_seconds.toFixed(1)}s</span>
            </span>
          )}
        </div>
      )}
    </div>
  );
};

export default SocControlPanel;
