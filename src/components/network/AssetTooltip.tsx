import { useLayoutEffect, useRef, useState } from 'react';
import { format } from 'date-fns';

export interface AssetTooltipNode {
  id: string;
  ip: string | null;
  hostname?: string | null;
  device_type: string;
  behavior_type?: string | null;
  vendor?: string | null;
  confidence?: number | null;
  risk_score?: number | null;
  vuln_count?: number | null;
  max_cvss?: number | null;
  last_seen?: string | null;
  status?: 'online' | 'offline';
}

interface AssetTooltipProps {
  node: AssetTooltipNode;
  position: { x: number; y: number };
}

const OFFSET = 14;
const MARGIN = 8;

const DEVICE_ACCENT: Record<string, string> = {
  Server: 'border-purple-500/40 ring-purple-500/20',
  Workstation: 'border-indigo-500/40 ring-indigo-500/20',
  IoMT: 'border-blue-500/40 ring-blue-500/20',
  IoT: 'border-amber-500/40 ring-amber-500/20',
  Network: 'border-emerald-500/40 ring-emerald-500/20',
  Unknown: 'border-slate-500/40 ring-slate-500/20',
};

const DEVICE_CHIP: Record<string, string> = {
  Server: 'bg-purple-500/15 text-purple-300',
  Workstation: 'bg-indigo-500/15 text-indigo-300',
  IoMT: 'bg-blue-500/15 text-blue-300',
  IoT: 'bg-amber-500/15 text-amber-300',
  Network: 'bg-emerald-500/15 text-emerald-300',
  Unknown: 'bg-slate-500/15 text-slate-300',
};

const vulnStyle = (vuln: number | null | undefined, cvss: number | null | undefined) => {
  const v = vuln ?? 0;
  const c = cvss ?? 0;
  if (v === 0) return { cls: 'text-emerald-400', dot: 'bg-emerald-400' };
  if (c >= 9) return { cls: 'text-rose-400', dot: 'bg-rose-400' };
  if (c >= 7) return { cls: 'text-orange-400', dot: 'bg-orange-400' };
  if (c >= 4) return { cls: 'text-amber-400', dot: 'bg-amber-400' };
  return { cls: 'text-emerald-400', dot: 'bg-emerald-400' };
};

const AssetTooltip = ({ node, position }: AssetTooltipProps) => {
  const ref = useRef<HTMLDivElement | null>(null);
  const [placed, setPlaced] = useState({ left: position.x + OFFSET, top: position.y + OFFSET });

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const { offsetWidth: w, offsetHeight: h } = el;
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    let left = position.x + OFFSET;
    let top = position.y + OFFSET;

    if (left + w + MARGIN > vw) left = position.x - w - OFFSET;
    if (top + h + MARGIN > vh) top = position.y - h - OFFSET;

    left = Math.max(MARGIN, Math.min(left, vw - w - MARGIN));
    top = Math.max(MARGIN, Math.min(top, vh - h - MARGIN));

    setPlaced({ left, top });
  }, [position.x, position.y, node.id]);

  const accent = DEVICE_ACCENT[node.device_type] ?? DEVICE_ACCENT.Unknown;
  const chip = DEVICE_CHIP[node.device_type] ?? DEVICE_CHIP.Unknown;

  const confPct = node.confidence == null
    ? null
    : Math.min(95, Math.round((node.confidence > 1 ? node.confidence : node.confidence * 100)));

  const vuln = vulnStyle(node.vuln_count, node.max_cvss);
  const vulnCount = node.vuln_count ?? 0;

  const lastSeen = node.last_seen
    ? (() => { try { return format(new Date(node.last_seen!), 'dd/MM/yyyy HH:mm'); } catch { return '—'; } })()
    : null;

  return (
    <div
      ref={ref}
      role="tooltip"
      className={`pointer-events-none fixed z-[60] w-[340px] rounded-xl border bg-slate-900/95 p-4 text-slate-100 shadow-lg ring-1 backdrop-blur-sm ${accent}`}
      style={{ left: placed.left, top: placed.top }}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`h-2.5 w-2.5 rounded-full ${node.status === 'online' ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          <span className="font-mono text-base font-semibold text-slate-100 truncate">{node.ip ?? '—'}</span>
        </div>
        <span className={`rounded px-2 py-0.5 text-xs font-medium ${chip}`}>
          {node.device_type || 'Unknown'}
        </span>
      </div>

      {node.hostname && (
        <p className="mt-1.5 truncate text-sm text-slate-300">{node.hostname}</p>
      )}

      <div className="mt-3 space-y-1.5 text-sm">
        {node.vendor && (
          <Row label="Vendor" value={<span className="text-slate-100 truncate">{node.vendor}</span>} />
        )}
        {node.behavior_type && (
          <Row label="Hành vi" value={<span className="text-slate-100">{node.behavior_type}</span>} />
        )}
        <Row
          label="Lỗ hổng (CVE)"
          value={
            <span className={`inline-flex items-center gap-1.5 font-semibold ${vuln.cls}`}>
              <span className={`h-2 w-2 rounded-full ${vuln.dot}`} />
              {vulnCount}
              {vulnCount > 0 && (node.max_cvss ?? 0) > 0 && (
                <span className="ml-1 font-normal text-slate-400">· CVSS tối đa {Number(node.max_cvss).toFixed(1)}</span>
              )}
            </span>
          }
        />
        {confPct !== null && (
          <Row label="Độ tin cậy" value={<span className="text-slate-100">{confPct}%</span>} />
        )}
        {lastSeen && (
          <Row label="Lần cuối" value={<span className="text-slate-300">{lastSeen}</span>} />
        )}
      </div>

      <div className="mt-3 border-t border-slate-700/60 pt-2 text-xs text-slate-400">
        Nhấp để xem chi tiết →
      </div>
    </div>
  );
};

const Row = ({ label, value }: { label: string; value: React.ReactNode }) => (
  <div className="flex items-center justify-between gap-3">
    <span className="text-sm text-slate-400">{label}</span>
    <span className="min-w-0 text-right">{value}</span>
  </div>
);

export default AssetTooltip;
