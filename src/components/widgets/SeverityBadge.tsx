interface SeverityBadgeProps {
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
}

const styles: Record<string, string> = {
  Critical: 'bg-critical/15 text-critical border-critical/30',
  High: 'bg-high/15 text-high border-high/30',
  Medium: 'bg-medium/15 text-medium border-medium/30',
  Low: 'bg-low/15 text-low border-low/30',
};

const SeverityBadge = ({ severity }: SeverityBadgeProps) => (
  <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${styles[severity]}`}>
    {severity}
  </span>
);

export default SeverityBadge;
