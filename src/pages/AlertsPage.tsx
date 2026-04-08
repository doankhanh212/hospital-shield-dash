import { useState, useEffect } from 'react';
import { Bell, CheckCircle2 } from 'lucide-react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import PageHeader from '@/components/widgets/PageHeader';
import EmptyState from '@/components/widgets/EmptyState';
import { TableSkeleton } from '@/components/widgets/Skeletons';
import { alerts } from '@/data/mockData';

const statusLabels: Record<string, string> = { new: 'Mới', investigating: 'Đang xử lý', resolved: 'Đã xử lý' };
const statusStyles: Record<string, string> = { new: 'bg-critical/10 text-critical', investigating: 'bg-warning/10 text-warning', resolved: 'bg-success/10 text-success' };

const AlertsPage = () => {
  const [statusFilter, setStatusFilter] = useState('Tất cả');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 600);
    return () => clearTimeout(t);
  }, []);

  const filtered = statusFilter === 'Tất cả' ? alerts : alerts.filter(a => a.status === statusFilter);

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Cảnh báo" description="Danh sách các sự kiện an ninh cần chú ý" />
        <TableSkeleton rows={7} cols={5} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cảnh báo"
        description={`${alerts.filter(a => a.status === 'new').length} cảnh báo mới cần xử lý`}
        actions={
          <div className="flex items-center gap-1.5">
            {['Tất cả', 'new', 'investigating', 'resolved'].map(s => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${statusFilter === s ? 'bg-primary text-primary-foreground shadow-sm' : 'bg-secondary text-secondary-foreground hover:bg-accent'}`}
              >
                {s === 'Tất cả' ? 'Tất cả' : statusLabels[s]}
              </button>
            ))}
          </div>
        }
      />

      {filtered.length === 0 ? (
        <EmptyState icon={CheckCircle2} title="Không có cảnh báo" description="Không có cảnh báo nào phù hợp với bộ lọc hiện tại." />
      ) : (
        <div className="space-y-2">
          {filtered.map(alert => (
            <div key={alert.id} className="rounded-lg border border-border bg-card p-4 transition-all hover:bg-accent/20 hover:border-border">
              <div className="flex items-start gap-3">
                <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                  alert.severity === 'Critical' ? 'bg-critical/10 text-critical' :
                  alert.severity === 'High' ? 'bg-high/10 text-high' :
                  alert.severity === 'Medium' ? 'bg-medium/10 text-medium' :
                  'bg-low/10 text-low'
                }`}>
                  <Bell size={15} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={alert.severity} />
                    <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">{alert.type}</span>
                    <span className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${statusStyles[alert.status]}`}>
                      {statusLabels[alert.status]}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-foreground leading-relaxed">{alert.message}</p>
                  <div className="mt-1.5 flex items-center gap-3 text-[11px] text-muted-foreground">
                    <span className="font-mono">{alert.source}</span>
                    <span>•</span>
                    <span>{alert.timestamp}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AlertsPage;
