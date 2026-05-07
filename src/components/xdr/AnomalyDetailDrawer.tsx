/**
 * Asset detail drawer — renders when an anomaly row is selected.
 * Shows asset metadata, behavior summary, full evidence JSON, and threat
 * intel bars.  Slide-in from right; closeable via X or ESC.
 */

import { useEffect } from 'react';
import {
  Activity, Cpu, Fingerprint, Globe, Network, ServerCog, X,
} from 'lucide-react';

import { type XdrAnomaly, fmtBytes, fmtRelativeTime, fmtType } from '@/lib/xdr';

import AssignmentSelect from './AssignmentSelect';
import NotesPanel from './NotesPanel';
import ScoreBar from './ScoreBar';
import SeverityChip from './SeverityChip';
import StatusBadge from './StatusBadge';
import ThreatIntelBars from './ThreatIntelBars';
import TimelinePanel from './TimelinePanel';
import TriageControls from './TriageControls';

interface Props {
  anomaly: XdrAnomaly | null;
  /** Other anomalies for the same asset, used to render a recent-history list. */
  related: XdrAnomaly[];
  onClose: () => void;
}

const Row = ({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) => (
  <div className="flex items-baseline justify-between gap-3 border-b border-border/40 py-1.5 text-xs last:border-b-0">
    <span className="text-muted-foreground">{label}</span>
    <span className={`text-foreground ${mono ? 'font-mono tabular-nums' : ''}`}>{value ?? '—'}</span>
  </div>
);

const AnomalyDetailDrawer = ({ anomaly, related, onClose }: Props) => {
  useEffect(() => {
    if (!anomaly) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [anomaly, onClose]);

  if (!anomaly) return null;

  const ev    = anomaly.evidence ?? {};
  const asset = anomaly.asset;
  const ports = ev.unique_ports;
  const dom   = ev.unique_domains;
  const bytes = ev.bytes_out;
  const ja3s  = ev.rare_ja3_sample as string[] | undefined;
  const rare_dom = ev.rare_domain_sample as string[] | undefined;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-background/60 backdrop-blur-sm" onClick={onClose} />

      {/* Drawer */}
      <aside
        className="fixed right-0 top-0 z-50 flex h-screen w-full max-w-[440px] flex-col border-l border-border bg-card shadow-2xl animate-in slide-in-from-right duration-200"
        role="dialog"
        aria-label="Anomaly detail"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip severity={anomaly.severity} size="md" />
              <StatusBadge status={anomaly.status} />
              {anomaly.assigned_to && (
                <span className="rounded-md border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                  @ {anomaly.assigned_to}
                </span>
              )}
              <h2 className="truncate text-sm font-semibold text-foreground">{fmtType(anomaly.type)}</h2>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{anomaly.description}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground transition"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 space-y-5 overflow-y-auto px-4 py-4">
          {/* Score */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Điểm tin cậy
            </h3>
            <ScoreBar score={anomaly.score} severity={anomaly.severity} />
          </section>

          {/* Triage controls */}
          <section>
            <TriageControls
              anomalyId={anomaly.id}
              assetId={anomaly.asset_id}
              current={anomaly.status}
            />
          </section>

          {/* Assignment */}
          <section>
            <AssignmentSelect
              anomalyId={anomaly.id}
              assetId={anomaly.asset_id}
              current={anomaly.assigned_to}
            />
          </section>

          {/* Notes */}
          <section>
            <NotesPanel
              anomalyId={anomaly.id}
              assetId={anomaly.asset_id}
              current={anomaly.note}
            />
          </section>

          {/* Timeline */}
          <section>
            <TimelinePanel assetId={anomaly.asset_id} />
          </section>

          {/* Asset */}
          <section>
            <h3 className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <Cpu size={11} /> Tài sản
            </h3>
            <div className="rounded-md border border-border bg-background/40 px-3 py-2">
              <Row label="IP"             value={anomaly.asset_id}                          mono />
              <Row label="MAC"            value={asset?.mac      ?? 'không rõ'}             mono />
              <Row label="Nhà sản xuất"   value={asset?.vendor   ?? 'không rõ'} />
              <Row label="Loại thiết bị"  value={asset?.device_type ?? 'chưa phân loại'} />
              <Row label="Độ tin cậy"     value={asset?.confidence != null ? `${asset.confidence.toFixed(0)}%` : '—'} mono />
            </div>
            {!asset && (
              <p className="mt-1 text-[11px] italic text-muted-foreground">
                IP chưa được liên kết với tài sản đã biết (bên ngoài hoặc chưa phân loại).
              </p>
            )}
          </section>

          {/* Behavior */}
          <section>
            <h3 className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <Activity size={11} /> Tóm tắt hành vi
            </h3>
            <div className="grid grid-cols-3 gap-2">
              <MetricTile icon={<Network  size={12} />} label="Cổng"     value={ports != null ? String(ports) : '—'} />
              <MetricTile icon={<Globe    size={12} />} label="Tên miền" value={dom   != null ? String(dom)   : '—'} />
              <MetricTile icon={<ServerCog size={12} />} label="Gửi đi"  value={bytes != null ? fmtBytes(bytes) : '—'} />
            </div>
            {ev.deviation && (
              <p className="mt-2 text-[11px] text-muted-foreground">
                Sai lệch khỏi ngưỡng: <span className="font-mono text-foreground">{ev.deviation.toFixed(2)}×</span>
                {ev.baseline_warm === false && (
                  <span className="ml-1 text-warning">(ngưỡng đang khởi động — dưới 5 mẫu)</span>
                )}
              </p>
            )}
            {ja3s && ja3s.length > 0 && (
              <div className="mt-3">
                <h4 className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <Fingerprint size={11} /> JA3 hiếm
                </h4>
                <div className="space-y-1">
                  {ja3s.slice(0, 5).map(j => (
                    <code key={j} className="block truncate rounded bg-muted px-2 py-1 font-mono text-[10px]">{j}</code>
                  ))}
                </div>
              </div>
            )}
            {rare_dom && rare_dom.length > 0 && (
              <div className="mt-3">
                <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Tên miền hiếm
                </h4>
                <div className="flex flex-wrap gap-1">
                  {rare_dom.slice(0, 8).map(d => (
                    <code key={d} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">{d}</code>
                  ))}
                </div>
              </div>
            )}
          </section>

          {/* Threat intel */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Tình báo mối đe dọa
            </h3>
            <ThreatIntelBars evidence={ev} />
          </section>

          {/* Related anomalies */}
          {related.length > 1 && (
            <section>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Bất thường gần đây của tài sản này
              </h3>
              <div className="space-y-1">
                {related.filter(r => r.id !== anomaly.id).slice(0, 5).map(r => (
                  <div key={r.id} className="flex items-center justify-between gap-2 rounded border border-border/60 bg-background/40 px-2 py-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <SeverityChip severity={r.severity} />
                      <span className="text-foreground">{fmtType(r.type)}</span>
                    </div>
                    <span className="font-mono text-[10px] text-muted-foreground">{fmtRelativeTime(r.last_seen)}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Raw evidence */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Bằng chứng thô
            </h3>
            <pre className="max-h-40 overflow-auto rounded-md border border-border bg-background/60 p-2 text-[10px] font-mono text-foreground">
              {JSON.stringify(ev, null, 2)}
            </pre>
          </section>
        </div>
      </aside>
    </>
  );
};

const MetricTile = ({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) => (
  <div className="rounded-md border border-border bg-background/40 px-2 py-1.5">
    <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
      {icon} {label}
    </div>
    <div className="mt-0.5 font-mono text-sm tabular-nums text-foreground">{value}</div>
  </div>
);

export default AnomalyDetailDrawer;
