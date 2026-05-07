import { type Severity, SEVERITY_TW } from '@/lib/xdr';

interface Props {
  /** Score 0..1 */
  score: number;
  /** If supplied, drives the bar colour; otherwise inferred from score. */
  severity?: Severity;
  showValue?: boolean;
}

function deriveSeverity(score: number): Severity {
  if (score >= 0.9) return 'critical';
  if (score >= 0.7) return 'high';
  if (score >= 0.4) return 'medium';
  return 'low';
}

const ScoreBar = ({ score, severity, showValue = true }: Props) => {
  const sev   = severity ?? deriveSeverity(score);
  const pct   = Math.max(0, Math.min(100, Math.round(score * 100)));
  const tone  = SEVERITY_TW[sev];
  return (
    <div className="flex items-center gap-2 min-w-[110px]">
      <div className="relative h-1.5 w-20 overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full rounded-full transition-all duration-300 ${tone.bar}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {showValue && (
        <span className={`font-mono text-[11px] tabular-nums ${tone.text}`}>
          {score.toFixed(2)}
        </span>
      )}
    </div>
  );
};

export default ScoreBar;
