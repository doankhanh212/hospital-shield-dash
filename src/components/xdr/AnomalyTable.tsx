/**
 * Real-time anomaly table — sortable, filterable, click-to-expand.
 *
 * Behavior:
 * - Newly-arrived anomalies (since last poll) get a brief highlight pulse.
 * - Severity filter + type filter narrow the list client-side.
 * - Sort column toggles asc/desc on click.
 * - Click row → calls onSelect(anomaly) so parent opens the drawer.
 */

import { useMemo, useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

import EmptyState from '@/components/widgets/EmptyState';
import {
  type AnomalyType,
  type Severity,
  type XdrAnomaly,
  SEVERITY_RANK,
  fmtRelativeTime,
  fmtType,
} from '@/lib/xdr';

import ScoreBar from './ScoreBar';
import SeverityChip from './SeverityChip';
import StatusBadge from './StatusBadge';
import ThreatIntelBars from './ThreatIntelBars';

interface Props {
  anomalies: XdrAnomaly[];
  loading?:  boolean;
  newIds?:   Set<string>;
  selectedId?: string | null;
  onSelect?: (a: XdrAnomaly) => void;
  /** Bound on rendered rows (perf). */
  maxRows?: number;
}

type SortKey = 'last_seen' | 'severity' | 'score' | 'type' | 'asset';

const ALL_TYPES: { value: AnomalyType | 'all'; label: string }[] = [
  { value: 'all',               label: 'Tất cả loại' },
  { value: 'port_scan',         label: 'Quét cổng' },
  { value: 'dns_spike',         label: 'Đột biến DNS' },
  { value: 'data_exfiltration', label: 'Rò rỉ dữ liệu' },
  { value: 'rare_ja3',          label: 'JA3 hiếm' },
  { value: 'rare_domain',       label: 'Tên miền hiếm' },
  { value: 'rogue_device',      label: 'Thiết bị lạ' },
];

const ALL_SEVS: { value: Severity | 'all'; label: string }[] = [
  { value: 'all',      label: 'Tất cả mức độ' },
  { value: 'critical', label: 'Nghiêm trọng' },
  { value: 'high',     label: 'Cao' },
  { value: 'medium',   label: 'Trung bình' },
  { value: 'low',      label: 'Thấp' },
];

const HEADERS: { key: SortKey; label: string; w: string; align?: 'right' }[] = [
  { key: 'last_seen', label: 'Thời gian',  w: 'w-[110px]' },
  { key: 'asset',     label: 'Tài sản',    w: 'w-[200px]' },
  { key: 'type',      label: 'Loại',       w: 'w-[140px]' },
  { key: 'severity',  label: 'Mức độ',     w: 'w-[100px]' },
  { key: 'score',     label: 'Điểm',       w: 'w-[140px]' },
];

const AnomalyTable = ({
  anomalies,
  loading = false,
  newIds,
  selectedId,
  onSelect,
  maxRows = 100,
}: Props) => {
  const [typeFilter,    setTypeFilter]    = useState<AnomalyType | 'all'>('all');
  const [sevFilter,     setSevFilter]     = useState<Severity | 'all'>('all');
  const [sortKey,       setSortKey]       = useState<SortKey>('last_seen');
  const [sortDir,       setSortDir]       = useState<'asc' | 'desc'>('desc');

  const filtered = useMemo(() => {
    let rows = anomalies;
    if (typeFilter !== 'all') rows = rows.filter(a => a.type === typeFilter);
    if (sevFilter  !== 'all') rows = rows.filter(a => a.severity === sevFilter);

    const dir = sortDir === 'asc' ? 1 : -1;
    rows = [...rows].sort((a, b) => {
      switch (sortKey) {
        case 'severity': return (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) * dir;
        case 'score':    return (a.score - b.score) * dir;
        case 'type':     return a.type.localeCompare(b.type) * dir;
        case 'asset':    return a.asset_id.localeCompare(b.asset_id) * dir;
        case 'last_seen':
        default:         return (new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime()) * dir;
      }
    });
    return rows.slice(0, maxRows);
  }, [anomalies, typeFilter, sevFilter, sortKey, sortDir, maxRows]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir(key === 'last_seen' ? 'desc' : 'desc'); }
  };

  const SortIcon = ({ k }: { k: SortKey }) =>
    k !== sortKey ? null : sortDir === 'asc' ? <ChevronUp size={11} /> : <ChevronDown size={11} />;

  return (
    <div className="rounded-lg border border-border bg-card">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-success" />
          Trực tiếp · {anomalies.length} mục
        </div>
        <div className="ml-auto flex items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as AnomalyType | 'all')}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {ALL_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <select
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value as Severity | 'all')}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {ALL_SEVS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </div>
      </div>

      {/* Table */}
      {loading && filtered.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm text-muted-foreground">Đang tải bất thường…</div>
      ) : filtered.length === 0 ? (
        <EmptyState
          title="Không có bất thường khớp bộ lọc"
          description="Hệ thống đang giám sát lưu lượng. Hãy nới lỏng bộ lọc loại / mức độ, hoặc chờ sự kiện mới."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-muted/30">
              <tr>
                {HEADERS.map(h => (
                  <th key={h.key} className={`${h.w} px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground`}>
                    <button
                      onClick={() => toggleSort(h.key)}
                      className="inline-flex items-center gap-1 hover:text-foreground transition-colors"
                    >
                      {h.label} <SortIcon k={h.key} />
                    </button>
                  </th>
                ))}
                <th className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Tình báo
                </th>
                <th className="w-[120px] px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Trạng thái
                </th>
                <th className="w-[110px] px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Phụ trách
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const isNew      = newIds?.has(a.id);
                const isSelected = selectedId === a.id;
                const isRogue    = a.type === 'rogue_device';
                return (
                  <tr
                    key={a.id}
                    onClick={() => onSelect?.(a)}
                    className={`cursor-pointer border-b border-border/60 transition-colors
                      ${isSelected ? 'bg-primary/10' : 'hover:bg-muted/30'}
                      ${isRogue ? 'bg-critical/5 border-l-2 border-l-critical' : ''}
                      ${isNew ? 'animate-pulse bg-low/10' : ''}`}
                  >
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground tabular-nums">
                      {fmtRelativeTime(a.last_seen)}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-[12px] text-foreground">{a.asset_id}</span>
                        {isRogue && (
                          <span className="inline-flex items-center rounded border border-critical/40 bg-critical/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-critical">
                            thiết bị mới
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-muted-foreground truncate max-w-[180px]">
                        {a.asset?.device_type ?? (a.asset?.vendor || 'Tài sản chưa xác định')}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-[12px] text-foreground">{fmtType(a.type)}</td>
                    <td className="px-3 py-2"><SeverityChip severity={a.severity} /></td>
                    <td className="px-3 py-2"><ScoreBar score={a.score} severity={a.severity} /></td>
                    <td className="px-3 py-2"><ThreatIntelBars evidence={a.evidence} compact /></td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1">
                        <StatusBadge status={a.status} />
                        {a.count > 1 && (
                          <span className="rounded border border-border bg-muted/40 px-1 py-0.5 text-[9px] text-muted-foreground tabular-nums">
                            ×{a.count}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      {a.assigned_to ? (
                        <span className="inline-flex items-center gap-1 rounded-md border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                          @{a.assigned_to}
                        </span>
                      ) : (
                        <span className="text-[10px] italic text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default AnomalyTable;
