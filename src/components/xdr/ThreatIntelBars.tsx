import { type AnomalyEvidence, intelTag, SEVERITY_TW } from '@/lib/xdr';
import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';

interface Props {
  evidence: AnomalyEvidence;
  compact?: boolean;
}

const ThreatIntelBars = ({ evidence, compact = false }: Props) => {
  const vtMal  = evidence.vt_malicious  ?? 0;
  const vtSusp = evidence.vt_suspicious ?? 0;
  const abuse  = evidence.abuse_score   ?? 0;

  const vtPct    = Math.min(100, Math.round(((vtMal + 0.5 * vtSusp) / 90) * 100));
  const abusePct = Math.max(0, Math.min(100, abuse));

  const tag      = intelTag(evidence);
  const tone     = SEVERITY_TW[tag.tone];
  const TagIcon  = tag.label === 'độc hại'
    ? ShieldAlert
    : tag.label === 'đáng ngờ'
    ? ShieldAlert
    : tag.label === 'chưa rõ'
    ? ShieldQuestion
    : ShieldCheck;

  if (compact) {
    return (
      <div className="flex items-center gap-1.5">
        <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-mono ${tone.bg} ${tone.text} ${tone.border}`}>
          VT&nbsp;<span className="font-semibold">{vtMal}</span>
        </span>
        <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-mono ${tone.bg} ${tone.text} ${tone.border}`}>
          AIB&nbsp;<span className="font-semibold">{abuse}</span>
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className={`flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs ${tone.bg} ${tone.text} ${tone.border}`}>
        <TagIcon size={14} />
        <span className="font-semibold uppercase tracking-wide">{tag.label}</span>
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground">VirusTotal — độc hại / đáng ngờ</span>
          <span className="font-mono tabular-nums text-foreground">{vtMal} / {vtSusp}</span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-muted">
          <div
            className={`h-full rounded-full transition-all duration-300 ${vtMal > 0 ? 'bg-critical' : vtSusp > 0 ? 'bg-high' : 'bg-low'}`}
            style={{ width: `${vtPct}%` }}
          />
        </div>
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground">AbuseIPDB — điểm tin cậy</span>
          <span className="font-mono tabular-nums text-foreground">{abuse} / 100</span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-muted">
          <div
            className={`h-full rounded-full transition-all duration-300 ${abuse >= 75 ? 'bg-critical' : abuse >= 25 ? 'bg-high' : 'bg-low'}`}
            style={{ width: `${abusePct}%` }}
          />
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelBars;
