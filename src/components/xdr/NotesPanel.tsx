/**
 * Notes panel — current note + quick add.  History (all prior notes) is
 * derived from the audit log via the timeline hook upstream.
 */

import { useState } from 'react';
import { MessageSquarePlus } from 'lucide-react';

import { useTriageActions } from '@/hooks/useXdr';

interface Props {
  anomalyId: string;
  assetId?: string | null;
  current: string | null;
}

const NotesPanel = ({ anomalyId, assetId, current }: Props) => {
  const { addNote } = useTriageActions(anomalyId, assetId);
  const [draft, setDraft] = useState('');

  const submit = () => {
    const v = draft.trim();
    if (!v) return;
    addNote.mutate(v, { onSuccess: () => setDraft('') });
  };

  return (
    <div>
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Ghi chú điều tra
      </h3>

      {current && (
        <div className="mb-2 rounded-md border border-border bg-background/40 px-2.5 py-1.5 text-xs italic text-foreground">
          “{current}”
        </div>
      )}

      <textarea
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="Thêm ghi chú điều tra…"
        rows={2}
        className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
      />
      <div className="mt-1 flex items-center gap-2">
        <button
          onClick={submit}
          disabled={addNote.isPending || !draft.trim()}
          className="inline-flex items-center gap-1 rounded-md border border-primary/40 bg-primary/10 px-2 py-1 text-[11px] font-medium text-primary transition hover:bg-primary/20 disabled:opacity-50"
        >
          <MessageSquarePlus size={12} />
          {addNote.isPending ? 'Đang lưu…' : 'Thêm ghi chú'}
        </button>
        {addNote.error && (
          <span className="text-[10px] text-critical">
            {(addNote.error as Error).message}
          </span>
        )}
      </div>
    </div>
  );
};

export default NotesPanel;
