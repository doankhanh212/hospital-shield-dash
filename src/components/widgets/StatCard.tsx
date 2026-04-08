import { type LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  variant?: 'default' | 'critical' | 'warning' | 'success' | 'info';
}

const variantStyles = {
  default: 'border-border bg-card hover:border-primary/30',
  critical: 'border-critical/20 bg-card hover:border-critical/40',
  warning: 'border-warning/20 bg-card hover:border-warning/40',
  success: 'border-success/20 bg-card hover:border-success/40',
  info: 'border-info/20 bg-card hover:border-info/40',
};

const iconStyles = {
  default: 'bg-primary/10 text-primary',
  critical: 'bg-critical/10 text-critical',
  warning: 'bg-warning/10 text-warning',
  success: 'bg-success/10 text-success',
  info: 'bg-info/10 text-info',
};

const StatCard = ({ title, value, icon: Icon, trend, variant = 'default' }: StatCardProps) => (
  <div className={`rounded-lg border p-4 transition-all duration-200 ${variantStyles[variant]}`}>
    <div className="flex items-start justify-between">
      <div className="space-y-1">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{title}</p>
        <p className="text-2xl font-bold tracking-tight text-foreground">{value}</p>
        {trend && <p className="text-[11px] text-muted-foreground">{trend}</p>}
      </div>
      <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${iconStyles[variant]}`}>
        <Icon size={18} />
      </div>
    </div>
  </div>
);

export default StatCard;
