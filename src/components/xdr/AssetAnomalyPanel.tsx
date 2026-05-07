/**
 * Inline XDR section for the legacy Asset Detail page.
 *
 * Filters the global anomaly stream by `asset_id == ip` and renders a tight
 * list with severity / status / score.  Renders an empty card when the IP
 * has no XDR signal — never blank.
 */

import { Radar } from 'lucide-react';

import { fmtRelativeTime, fmtType } from '@/lib/xdr';
import { useAnomalies } from '@/hooks/useXdr';

import ScoreBar from './ScoreBar';
import SeverityChip from './SeverityChip';
import StatusBadge from './StatusBadge';

interface Props {
  ip: string | null;
}

const AssetAnomalyPanel = ({ ip }: Props) => {
  const { data, isLoading } = useAnomalies({ asset_id: ip ?? undefined, limit: 50 }, 5_000);
  const items = data?.items ?? [];

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Radar size={14} className="text-primary" />
          <h2 className="text-sm font-semibold text-foreground">Threat Activity (XDR)</h2>
        </div>
        <span className="text-[10px] text-muted-foreground">{items.length} anomalies · live</span>
      </div>

      {!ip ? (
        <p className="px-4 py-6 text-center text-xs italic text-muted-foreground">
          Asset has no IP — XDR cannot correlate.
        </p>
      ) : isLoading && items.length === 0 ? (
        <p className="px-4 py-6 text-center text-xs text-muted-foreground">Loading…</p>
      ) : items.length === 0 ? (
        <p className="px-4 py-6 text-center text-xs italic text-muted-foreground">
          No anomalies detected for this asset. Behaviour is within baseline.
        </p>
      ) : (
        <ul className="divide-y divide-border/60">
          {items.map(a => (
            <li key={a.id} className="flex items-center gap-3 px-4 py-2 text-xs">
              <SeverityChip severity={a.severity} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-foreground">{fmtType(a.type)}</span>
                  <StatusBadge status={a.status} />
                  {a.assigned_to && (
                    <span className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                      @{a.assigned_to}
                    </span>
                  )}
                </div>
                <p className="truncate text-[10px] text-muted-foreground">{a.description}</p>
              </div>
              <ScoreBar score={a.score} severity={a.severity} />
              <span className="font-mono text-[10px] text-muted-foreground">{fmtRelativeTime(a.last_seen)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default AssetAnomalyPanel;
