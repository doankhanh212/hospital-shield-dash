import { type Severity, SEVERITY_TW } from '@/lib/xdr';

interface Props {
  severity: Severity;
  size?: 'sm' | 'md';
  className?: string;
}

/** Colour-coded severity pill — lowercase severity strings from the XDR API. */
const SeverityChip = ({ severity, size = 'sm', className = '' }: Props) => {
  const t = SEVERITY_TW[severity];
  const dim = size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]';
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border font-semibold uppercase tracking-wide ${t.bg} ${t.text} ${t.border} ${dim} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${t.bar}`} />
      {severity}
    </span>
  );
};

export default SeverityChip;
