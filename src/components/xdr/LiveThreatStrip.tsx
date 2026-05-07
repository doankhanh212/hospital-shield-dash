/**
 * Compact "Live Threat Activity" strip for the main Dashboard.
 *
 * Shows: counts by severity, the 5 most recent anomalies, "view all"
 * link to /xdr.  Always polls every 5 s.  Renders an empty-state card
 * (never blank) when there is nothing to show.
 */

import { useNavigate } from 'react-router-dom';
import { Activity, ChevronRight, Radar } from 'lucide-react';

import {
  type Severity,
  fmtRelativeTime,
  fmtType,
} from '@/lib/xdr';
import { useAnomalies } from '@/hooks/useXdr';
import SeverityChip from './SeverityChip';
import StatusBadge from './StatusBadge';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

const LiveThreatStrip = () => {
  const nav = useNavigate();
  const { data, isLoading } = useAnomalies({ limit: 100 }, 5_000);
  const items = data?.items ?? [];

  const counts = SEVERITIES.reduce<Record<Severity, number>>((acc, s) => {
    acc[s] = items.filter(a => a.severity === s).length;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const recent = items.slice(0, 5);

  return (
    <div className="rounded-lg border border-border bg-card">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-primary" />
          <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground">
            Live Threat Activity
          </h2>
          <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-success" />
        </div>
        <button
          onClick={() => nav('/xdr')}
          className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] text-muted-foreground hover:text-foreground hover:bg-muted/30 transition"
        >
          XDR Command <ChevronRight size={11} />
        </button>
      </div>

      {/* Severity strip */}
      <div className="grid grid-cols-4 gap-2 border-b border-border px-4 py-3">
        {SEVERITIES.map(s => (
          <div key={s} className="text-center">
            <SeverityChip severity={s} />
            <p className="mt-1 font-mono text-lg font-bold tabular-nums text-foreground">
              {counts[s]}
            </p>
          </div>
        ))}
      </div>

      {/* Recent list */}
      <div>
        {isLoading && recent.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-muted-foreground">
            Loading…
          </div>
        ) : recent.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-muted-foreground">
            <Radar size={18} className="mx-auto mb-1 text-muted-foreground/60" />
            System is monitoring traffic — no threats detected.
          </div>
        ) : (
          <ul className="divide-y divide-border/60">
            {recent.map(a => (
              <li
                key={a.id}
                onClick={() => nav('/xdr')}
                className="flex cursor-pointer items-center gap-3 px-4 py-2 text-xs transition hover:bg-muted/30"
              >
                <SeverityChip severity={a.severity} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-foreground">{a.asset_id}</span>
                    <span className="text-foreground">{fmtType(a.type)}</span>
                  </div>
                  <p className="truncate text-[10px] text-muted-foreground">{a.description}</p>
                </div>
                <StatusBadge status={a.status} />
                <span className="font-mono text-[10px] text-muted-foreground">
                  {fmtRelativeTime(a.last_seen)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default LiveThreatStrip;
