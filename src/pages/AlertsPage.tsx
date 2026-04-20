import { useState } from 'react';
import { Bell, CheckCircle2, RefreshCw, AlertCircle, X } from 'lucide-react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import PageHeader from '@/components/widgets/PageHeader';
import EmptyState from '@/components/widgets/EmptyState';
import { TableSkeleton } from '@/components/widgets/Skeletons';
import { useAlerts, useAlertCounts, useUpdateAlert } from '@/hooks/useApi';
import { AlertItem } from '@/lib/api';
import { format } from 'date-fns';

const statusLabels: Record<string, string> = {
  new: 'Mới',
  investigating: 'Đang xử lý',
  resolved: 'Đã xử lý',
  false_positive: 'False Positive',
};
const statusStyles: Record<string, string> = {
  new: 'bg-critical/10 text-critical',
  investigating: 'bg-warning/10 text-warning',
  resolved: 'bg-success/10 text-success',
  false_positive: 'bg-muted text-muted-foreground',
};

const typeLabels: Record<string, string> = {
  vulnerability: 'Lỗ hổng (CVE)',
  new_asset: 'Thiết bị mới',
  unusual_port: 'Cổng bất thường',
  external_connection: 'Kết nối ra ngoài',
};

const PAGE_SIZE = 50;

const AlertsPage = () => {
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);
  const [fpDialog, setFpDialog] = useState<AlertItem | null>(null);
  const offset = (page - 1) * PAGE_SIZE;

  const { data, isLoading, isError, error, refetch } = useAlerts({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    limit: PAGE_SIZE,
    offset,
  });
  const { data: counts } = useAlertCounts();
  const updateAlert = useUpdateAlert();

  const alerts = data?.items ?? [];
  const total = data?.total ?? 0;
  const newCount = counts?.by_status?.find(s => s.status === 'new')?.count ?? 0;

  const handleMarkFalsePositive = (alert: AlertItem, note: string) => {
    updateAlert.mutate(
      { id: alert.id, status: 'false_positive', note },
      { onSuccess: () => setFpDialog(null) },
    );
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Cảnh báo lỗ hổng" description="Danh sách các lỗ hổng (CVE) phát hiện trên tài sản" />
        <TableSkeleton rows={7} cols={5} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader title="Cảnh báo lỗ hổng" description="Danh sách các lỗ hổng (CVE) phát hiện trên tài sản" />
        <div className="flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <AlertCircle size={16} />
          <span>Lỗi tải cảnh báo: {error instanceof Error ? error.message : 'Unknown error'}</span>
          <button onClick={() => refetch()} className="ml-auto text-xs underline">Thử lại</button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cảnh báo lỗ hổng"
        description={`${newCount} cảnh báo lỗ hổng mới cần xử lý`}
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            {/* Status filters */}
            <div className="flex items-center gap-1.5">
              {[
                { value: '', label: 'Tất cả' },
                { value: 'new', label: 'Mới' },
                { value: 'false_positive', label: 'False Positive' },
              ].map(s => (
                <button
                  key={s.value}
                  onClick={() => { setStatusFilter(s.value); setPage(1); }}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${statusFilter === s.value ? 'bg-primary text-primary-foreground shadow-sm' : 'bg-secondary text-secondary-foreground hover:bg-accent'}`}
                >
                  {s.label}
                </button>
              ))}
            </div>
            {/* Severity filter */}
            <select
              value={severityFilter}
              onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}
              className="rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-foreground focus:border-primary focus:outline-none transition-colors"
            >
              <option value="">Mức độ: Tất cả</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button
              onClick={() => refetch()}
              className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw size={12} />
            </button>
          </div>
        }
      />

      {/* Counts summary bar */}
      {counts && (
        <div className="flex flex-wrap gap-3">
          {counts.by_severity.map(s => (
            <button
              key={s.severity}
              onClick={() => { setSeverityFilter(sv => sv === s.severity ? '' : s.severity); setPage(1); }}
              className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-all ${severityFilter === s.severity ? 'ring-2 ring-primary ring-offset-1 ring-offset-background' : ''} ${
                s.severity === 'critical' ? 'border-critical/20 bg-critical/10 text-critical' :
                s.severity === 'high' ? 'border-high/20 bg-high/10 text-high' :
                s.severity === 'medium' ? 'border-medium/20 bg-medium/10 text-medium' :
                'border-border bg-card text-muted-foreground'
              }`}
            >
              {s.severity.charAt(0).toUpperCase() + s.severity.slice(1)}: {s.count}
            </button>
          ))}
        </div>
      )}

      {alerts.length === 0 ? (
        <EmptyState icon={CheckCircle2} title="Không có cảnh báo" description="Không có cảnh báo nào phù hợp với bộ lọc hiện tại." />
      ) : (
        <div className="space-y-2">
          {alerts.map(alert => (
            <AlertCard key={alert.id} alert={alert} onMarkFalsePositive={() => setFpDialog(alert)} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{total} cảnh báo · Trang {page} / {Math.ceil(total / PAGE_SIZE)}</span>
          <div className="flex gap-2">
            <button
              disabled={page === 1}
              onClick={() => setPage(p => p - 1)}
              className="rounded-lg border border-border bg-card px-3 py-1.5 disabled:opacity-40 hover:bg-accent transition-colors"
            >‹ Trước</button>
            <button
              disabled={page * PAGE_SIZE >= total}
              onClick={() => setPage(p => p + 1)}
              className="rounded-lg border border-border bg-card px-3 py-1.5 disabled:opacity-40 hover:bg-accent transition-colors"
            >Sau ›</button>
          </div>
        </div>
      )}

      {fpDialog && (
        <FalsePositiveDialog
          alert={fpDialog}
          onClose={() => setFpDialog(null)}
          onSubmit={note => handleMarkFalsePositive(fpDialog, note)}
          submitting={updateAlert.isPending}
        />
      )}
    </div>
  );
};

const AlertCard = ({
  alert,
  onMarkFalsePositive,
}: {
  alert: AlertItem;
  onMarkFalsePositive: () => void;
}) => {
  const sev = alert.severity?.toLowerCase() ?? 'medium';
  const iconBg =
    sev === 'critical' ? 'bg-critical/10 text-critical' :
    sev === 'high'     ? 'bg-high/10 text-high' :
    sev === 'medium'   ? 'bg-medium/10 text-medium' :
                         'bg-low/10 text-low';

  const ts = alert.created_at
    ? format(new Date(alert.created_at), 'dd/MM/yyyy HH:mm')
    : '—';

  const note = (alert.metadata && typeof alert.metadata === 'object'
    ? (alert.metadata as Record<string, unknown>).note
    : null) as string | null | undefined;

  const isFalsePositive = alert.status === 'false_positive';

  return (
    <div className="rounded-lg border border-border bg-card p-4 transition-all hover:bg-accent/20">
      <div className="flex items-start gap-3">
        <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${iconBg}`}>
          <Bell size={15} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={alert.severity as 'Critical' | 'High' | 'Medium' | 'Low'} />
            <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
              {typeLabels[alert.alert_type] ?? alert.alert_type}
            </span>
            <span className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${statusStyles[alert.status] ?? 'bg-muted text-muted-foreground'}`}>
              {statusLabels[alert.status] ?? alert.status}
            </span>
          </div>
          <p className="mt-2 text-sm text-foreground leading-relaxed">{alert.message}</p>
          <div className="mt-1.5 flex items-center gap-3 text-[11px] text-muted-foreground">
            {alert.source_ip && <span className="font-mono">{alert.source_ip}</span>}
            {alert.source_ip && <span>•</span>}
            <span>{ts}</span>
          </div>
          {isFalsePositive && note && (
            <div className="mt-2 rounded-md border border-border bg-muted/40 p-2 text-[11px] text-muted-foreground">
              <span className="font-medium text-foreground">Ghi chú:</span> {note}
            </div>
          )}
        </div>
        {!isFalsePositive && (
          <button
            onClick={onMarkFalsePositive}
            className="ml-2 shrink-0 rounded-lg border border-border bg-background px-3 py-1.5 text-[11px] font-medium text-foreground hover:bg-accent transition-colors"
          >
            False Positive
          </button>
        )}
      </div>
    </div>
  );
};

const FalsePositiveDialog = ({
  alert,
  onClose,
  onSubmit,
  submitting,
}: {
  alert: AlertItem;
  onClose: () => void;
  onSubmit: (note: string) => void;
  submitting: boolean;
}) => {
  const [note, setNote] = useState('');

  const handleSubmit = () => {
    const trimmed = note.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-lg border border-border bg-card p-5 shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">Đánh dấu False Positive</h2>
            <p className="mt-1 text-xs text-muted-foreground">Nhập ghi chú giải thích lý do cảnh báo này là false positive.</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        <div className="mt-3 rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
          <p className="text-foreground">{alert.message}</p>
          {alert.source_ip && <p className="mt-1 font-mono">{alert.source_ip}</p>}
        </div>

        <label className="mt-4 block text-xs font-medium text-foreground">
          Ghi chú <span className="text-critical">*</span>
        </label>
        <textarea
          value={note}
          onChange={e => setNote(e.target.value)}
          placeholder="VD: Thiết bị đã được vá, không chạy dịch vụ ảnh hưởng, môi trường lab..."
          rows={4}
          className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none transition-colors resize-none"
          autoFocus
        />

        <div className="mt-4 flex items-center justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg border border-border bg-background px-3 py-1.5 text-xs font-medium text-foreground hover:bg-accent transition-colors"
          >
            Hủy
          </button>
          <button
            onClick={handleSubmit}
            disabled={!note.trim() || submitting}
            className="rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {submitting ? 'Đang lưu...' : 'Xác nhận'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlertsPage;
