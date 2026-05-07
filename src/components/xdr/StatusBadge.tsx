import { type TriageStatus, STATUS_TONE } from '@/lib/xdr';

interface Props {
  status: TriageStatus;
  className?: string;
}

const StatusBadge = ({ status, className = '' }: Props) => {
  const t = STATUS_TONE[status] ?? STATUS_TONE.new;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${t.cls} ${className}`}
    >
      {t.label}
    </span>
  );
};

export default StatusBadge;
