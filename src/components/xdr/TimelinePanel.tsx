/**
 * Vertical incident timeline — merges anomaly + analyst-action events
 * for a single asset.  Polls every 5s via useAssetTimeline.
 */

import { Activity, ArrowRightCircle, Clock, MessageSquare, Radar, UserCheck } from 'lucide-react';

import { type TimelineEvent, fmtRelativeTime } from '@/lib/xdr';
import { useAssetTimeline } from '@/hooks/useXdr';

interface Props {
  assetId: string | null;
}

function eventVisuals(e: TimelineEvent): { icon: React.ReactNode; tone: string } {
  if (e.type === 'anomaly') {
    return { icon: <Radar size={12} />, tone: 'border-primary/40 bg-primary/10 text-primary' };
  }
  const action = (e.details as { action?: string }).action;
  if (action === 'assign')
    return { icon: <UserCheck size={12} />, tone: 'border-medium/40 bg-medium/10 text-medium' };
  if (action === 'note')
    return { icon: <MessageSquare size={12} />, tone: 'border-low/40 bg-low/10 text-low' };
  if (action === 'status_change')
    return { icon: <ArrowRightCircle size={12} />, tone: 'border-high/40 bg-high/10 text-high' };
  return { icon: <Activity size={12} />, tone: 'border-border bg-muted text-muted-foreground' };
}

const TimelinePanel = ({ assetId }: Props) => {
  const q = useAssetTimeline(assetId);
  const events = q.data?.items ?? [];

  return (
    <div>
      <h3 className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        <Clock size={11} /> Dòng thời gian tài sản
      </h3>

      {q.isLoading && events.length === 0 ? (
        <p className="text-xs text-muted-foreground">Đang tải dòng thời gian…</p>
      ) : events.length === 0 ? (
        <p className="text-xs italic text-muted-foreground">Chưa có sự kiện nào cho tài sản này.</p>
      ) : (
        <ol className="relative space-y-2 border-l border-border pl-4">
          {events.map((e, i) => {
            const v = eventVisuals(e);
            return (
              <li key={`${e.time}-${i}`} className="relative">
                <span className={`absolute -left-[22px] flex h-4 w-4 items-center justify-center rounded-full border ${v.tone}`}>
                  {v.icon}
                </span>
                <div className="rounded-md border border-border bg-background/40 px-2.5 py-1.5">
                  <div className="flex items-baseline justify-between gap-2">
                    <p className="truncate text-xs text-foreground">{e.description}</p>
                    <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                      {fmtRelativeTime(e.time)}
                    </span>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
};

export default TimelinePanel;
