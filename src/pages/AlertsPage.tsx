import { useState } from 'react';
import { Bell, CheckCircle, Search as SearchIcon } from 'lucide-react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import { alerts } from '@/data/mockData';

const statusLabels: Record<string, string> = {
  new: 'Mới',
  investigating: 'Đang xử lý',
  resolved: 'Đã xử lý',
};

const statusStyles: Record<string, string> = {
  new: 'bg-critical/10 text-critical',
  investigating: 'bg-warning/10 text-warning',
  resolved: 'bg-success/10 text-success',
};

const AlertsPage = () => {
  const [statusFilter, setStatusFilter] = useState('Tất cả');

  const filtered = statusFilter === 'Tất cả' ? alerts : alerts.filter(a => a.status === statusFilter);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-foreground">Cảnh báo</h2>
          <p className="text-sm text-muted-foreground">Danh sách các sự kiện an ninh cần chú ý</p>
        </div>
        <div className="flex items-center gap-2">
          {['Tất cả', 'new', 'investigating', 'resolved'].map(s => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${statusFilter === s ? 'bg-primary text-primary-foreground' : 'bg-secondary text-secondary-foreground hover:bg-accent'}`}
            >
              {s === 'Tất cả' ? 'Tất cả' : statusLabels[s]}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        {filtered.map(alert => (
          <div key={alert.id} className="rounded-lg border border-border bg-card p-4 transition-all hover:bg-accent/30">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3 min-w-0">
                <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${alert.severity === 'Critical' ? 'bg-critical/10 text-critical' : alert.severity === 'High' ? 'bg-high/10 text-high' : alert.severity === 'Medium' ? 'bg-medium/10 text-medium' : 'bg-low/10 text-low'}`}>
                  <Bell size={16} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={alert.severity} />
                    <span className="rounded bg-accent px-1.5 py-0.5 text-[10px] font-medium text-accent-foreground">{alert.type}</span>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${statusStyles[alert.status]}`}>
                      {statusLabels[alert.status]}
                    </span>
                  </div>
                  <p className="mt-1.5 text-sm text-foreground">{alert.message}</p>
                  <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="font-mono">{alert.source}</span>
                    <span>{alert.timestamp}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AlertsPage;
