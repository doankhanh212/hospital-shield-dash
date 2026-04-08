import { type LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  variant?: 'default' | 'critical' | 'warning' | 'success';
}

const variantStyles = {
  default: 'border-border bg-card',
  critical: 'border-critical/30 bg-critical/5 glow-red',
  warning: 'border-warning/30 bg-warning/5',
  success: 'border-success/30 bg-success/5',
};

const iconStyles = {
  default: 'bg-primary/10 text-primary',
  critical: 'bg-critical/10 text-critical',
  warning: 'bg-warning/10 text-warning',
  success: 'bg-success/10 text-success',
};

const StatCard = ({ title, value, icon: Icon, trend, variant = 'default' }: StatCardProps) => (
  <div className={`rounded-lg border p-5 transition-all duration-200 hover:scale-[1.02] ${variantStyles[variant]}`}>
    <div className="flex items-center justify-between">
      <div>
        <p className="text-xs font-medium text-muted-foreground">{title}</p>
        <p className="mt-1 text-2xl font-bold text-foreground">{value}</p>
        {trend && <p className="mt-1 text-xs text-muted-foreground">{trend}</p>}
      </div>
      <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${iconStyles[variant]}`}>
        <Icon size={20} />
      </div>
    </div>
  </div>
);

export default StatCard;
