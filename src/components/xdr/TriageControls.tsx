/**
 * Triage button row — 1-click status changes.
 *
 * Each button calls the corresponding mutation; the active status is
 * highlighted; disabled while the network call is in flight.
 */

import { AlertTriangle, CheckCircle2, Search, ShieldOff } from 'lucide-react';

import { type TriageStatus } from '@/lib/xdr';
import { useTriageActions } from '@/hooks/useXdr';

interface Props {
  anomalyId: string;
  assetId?: string | null;
  current: TriageStatus;
}

const BUTTONS: { status: TriageStatus; label: string; icon: typeof Search; cls: string }[] = [
  { status: 'investigating',  label: 'Investigating', icon: Search,         cls: 'border-medium/40 text-medium hover:bg-medium/15' },
  { status: 'escalated',      label: 'Escalate',      icon: AlertTriangle,  cls: 'border-high/40   text-high   hover:bg-high/15' },
  { status: 'resolved',       label: 'Resolve',       icon: CheckCircle2,   cls: 'border-success/40 text-success hover:bg-success/15' },
  { status: 'false_positive', label: 'False Positive',icon: ShieldOff,      cls: 'border-border    text-muted-foreground hover:bg-muted/30' },
];

const TriageControls = ({ anomalyId, assetId, current }: Props) => {
  const { setStatus } = useTriageActions(anomalyId, assetId);
  const pending = setStatus.isPending;

  return (
    <div>
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Triage Actions
      </h3>
      <div className="grid grid-cols-2 gap-2">
        {BUTTONS.map(b => {
          const active = current === b.status;
          const Icon   = b.icon;
          return (
            <button
              key={b.status}
              disabled={pending || active}
              onClick={() => setStatus.mutate(b.status)}
              className={`group flex items-center justify-center gap-1.5 rounded-md border px-2 py-1.5 text-xs font-medium transition
                ${active
                  ? 'cursor-default opacity-60 bg-muted/40 border-border text-foreground'
                  : `bg-background ${b.cls}`}
                ${pending && !active ? 'opacity-50 cursor-wait' : ''}`}
            >
              <Icon size={12} />
              {b.label}
              {active && <span className="ml-1 text-[10px] uppercase tracking-wider">·current</span>}
            </button>
          );
        })}
      </div>
      {setStatus.error && (
        <p className="mt-1 text-[10px] text-critical">
          Failed to update: {(setStatus.error as Error).message}
        </p>
      )}
    </div>
  );
};

export default TriageControls;
