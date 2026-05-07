/**
 * Incident panel — groups correlated anomaly bursts (server-side correlation
 * already wrote rows into xdr_incidents).  Each card shows the asset, the
 * involved anomaly types, severity, and a relative timeline.
 */

import { Flame } from 'lucide-react';

import EmptyState from '@/components/widgets/EmptyState';
import { type XdrIncident, fmtRelativeTime, fmtType } from '@/lib/xdr';

import SeverityChip from './SeverityChip';

interface Props {
  incidents: XdrIncident[];
  loading?:  boolean;
  onSelectAsset?: (assetId: string) => void;
}

const IncidentPanel = ({ incidents, loading = false, onSelectAsset }: Props) => {
  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Flame size={14} className="text-critical" />
        <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground">
          Sự cố đang hoạt động
        </h2>
        <span className="ml-auto text-xs text-muted-foreground">{incidents.length}</span>
      </div>

      <div className="max-h-[420px] overflow-y-auto">
        {loading && incidents.length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-muted-foreground">Đang tải sự cố…</div>
        ) : incidents.length === 0 ? (
          <div className="px-2">
            <EmptyState
              title="Không có sự cố hoạt động"
              description="Sự cố hình thành khi một tài sản phát ≥ 2 loại bất thường khác nhau trong 5 phút."
            />
          </div>
        ) : (
          <ul className="divide-y divide-border/60">
            {incidents.map(inc => {
              const opened = fmtRelativeTime(inc.first_seen);
              const last   = fmtRelativeTime(inc.last_seen);
              return (
                <li
                  key={inc.id}
                  onClick={() => onSelectAsset?.(inc.asset_id)}
                  className="cursor-pointer px-3 py-2.5 transition-colors hover:bg-muted/30"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <SeverityChip severity={inc.severity} />
                        <span className="truncate font-mono text-xs text-foreground">{inc.asset_id}</span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {inc.anomaly_types.map(t => (
                          <span
                            key={t}
                            className="rounded border border-border bg-background/60 px-1.5 py-0.5 text-[10px] text-foreground"
                          >
                            {fmtType(t)}
                          </span>
                        ))}
                      </div>
                      {inc.asset?.device_type && (
                        <p className="mt-1 truncate text-[11px] text-muted-foreground">
                          {inc.asset.device_type}{inc.asset.vendor ? ` · ${inc.asset.vendor}` : ''}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="mt-2 flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span>mở lúc <span className="text-foreground">{opened}</span></span>
                    <span className="opacity-30">·</span>
                    <span>mới nhất <span className="text-foreground">{last}</span></span>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
};

export default IncidentPanel;
