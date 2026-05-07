/**
 * Assignment dropdown — pick from a fixed roster of analysts (mirrors the
 * spec) plus an "unassign" option.  Defaults to the currently logged-in
 * user when known.  Updates immediately on selection.
 */

import { UserCircle2 } from 'lucide-react';

import { authStorage } from '@/lib/auth';
import { useTriageActions } from '@/hooks/useXdr';

const DEFAULT_ROSTER = ['khanh', 'analyst1', 'analyst2'];

interface Props {
  anomalyId: string;
  assetId?: string | null;
  current: string | null;
}

const AssignmentSelect = ({ anomalyId, assetId, current }: Props) => {
  const { assign } = useTriageActions(anomalyId, assetId);
  const me = authStorage.getUser()?.username ?? null;
  const roster = Array.from(new Set([me, ...DEFAULT_ROSTER].filter(Boolean) as string[]));

  return (
    <div>
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Phân công
      </h3>
      <div className="flex items-center gap-2">
        <UserCircle2 size={14} className="text-muted-foreground" />
        <select
          value={current ?? ''}
          disabled={assign.isPending}
          onChange={(e) => {
            const v = e.target.value;
            assign.mutate(v === '' ? null : v);
          }}
          className="flex-1 rounded-md border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="">— chưa phân công —</option>
          {roster.map(u => (
            <option key={u} value={u}>{u}{u === me ? ' (tôi)' : ''}</option>
          ))}
        </select>
        {me && current !== me && (
          <button
            disabled={assign.isPending}
            onClick={() => assign.mutate(me)}
            className="rounded-md border border-primary/40 bg-primary/10 px-2 py-1 text-[11px] font-medium text-primary hover:bg-primary/20 transition disabled:opacity-50"
          >
            Nhận xử lý
          </button>
        )}
      </div>
      {assign.error && (
        <p className="mt-1 text-[10px] text-critical">
          Lỗi: {(assign.error as Error).message}
        </p>
      )}
    </div>
  );
};

export default AssignmentSelect;
