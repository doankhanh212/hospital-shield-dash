import { useState } from 'react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import PageHeader from '@/components/widgets/PageHeader';
import EmptyState from '@/components/widgets/EmptyState';
import { TableSkeleton, StatCardsSkeleton } from '@/components/widgets/Skeletons';
import { useVulnerabilities } from '@/hooks/useApi';
import { Bug, AlertCircle, RefreshCw } from 'lucide-react';

const SMAP: Record<string, { label: string; score: [number, number] }> = {
  critical: { label: 'Critical', score: [9, 10] },
  high:     { label: 'High',     score: [7, 8.9] },
  medium:   { label: 'Medium',   score: [4, 6.9] },
  low:      { label: 'Low',      score: [0, 3.9] },
};

const cvssColor = (score: number | null) =>
  !score ? 'text-muted-foreground' :
  score >= 9 ? 'text-critical' :
  score >= 7 ? 'text-high' :
  score >= 4 ? 'text-medium' : 'text-low';

const VulnerabilitiesPage = () => {
  const [severityFilter, setSeverityFilter] = useState('');

  const { data, isLoading, isError, error, refetch } = useVulnerabilities({
    severity: severityFilter || undefined,
    limit: 500,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  items.forEach(v => {
    const s = (v.severity ?? '').toLowerCase();
    if (s in counts) counts[s]++;
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Quản lý lỗ hổng" description="Danh sách CVE ảnh hưởng đến thiết bị trong mạng" />
        <StatCardsSkeleton />
        <TableSkeleton rows={7} cols={6} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader title="Quản lý lỗ hổng" description="Danh sách CVE ảnh hưởng đến thiết bị trong mạng" />
        <div className="flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <AlertCircle size={16} />
          <span>Lỗi tải lỗ hổng: {error instanceof Error ? error.message : 'Unknown error'}</span>
          <button onClick={() => refetch()} className="ml-auto text-xs underline">Thử lại</button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quản lý lỗ hổng"
        description={`${total} lỗ hổng đã phát hiện`}
        actions={
          <button onClick={() => refetch()} className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <RefreshCw size={13} /> Làm mới
          </button>
        }
      />

      {/* Severity summary cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(f => f === sev ? '' : sev)}
            className={`rounded-lg border p-4 text-center transition-all duration-150 hover:scale-[1.01] ${severityFilter === sev ? 'ring-2 ring-primary ring-offset-1 ring-offset-background' : ''} ${
              sev === 'critical' ? 'border-critical/20 bg-card' :
              sev === 'high'     ? 'border-high/20 bg-card' :
              sev === 'medium'   ? 'border-medium/20 bg-card' :
                                   'border-low/20 bg-card'
            }`}
          >
            <p className={`text-2xl font-bold ${sev === 'critical' ? 'text-critical' : sev === 'high' ? 'text-high' : sev === 'medium' ? 'text-medium' : 'text-low'}`}>
              {counts[sev]}
            </p>
            <p className="text-[11px] text-muted-foreground mt-1 font-medium">{SMAP[sev].label}</p>
          </button>
        ))}
      </div>

      {items.length === 0 ? (
        <EmptyState
          icon={Bug}
          title="Không có lỗ hổng"
          description={severityFilter ? `Không tìm thấy lỗ hổng mức ${severityFilter}.` : 'Chưa có dữ liệu CVE. Hãy chạy đồng bộ NVD trước.'}
        />
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-3">CVE</th>
                  <th className="px-4 py-3">CVSS</th>
                  <th className="px-4 py-3">Mức độ</th>
                  <th className="px-4 py-3">Mô tả</th>
                  <th className="px-4 py-3 text-center">Thiết bị</th>
                </tr>
              </thead>
              <tbody>
                {items.map(v => (
                  <tr key={v.id} className="border-b border-border/30 transition-colors hover:bg-accent/40">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Bug size={13} className="text-muted-foreground" />
                        <span className="font-mono text-xs font-semibold text-foreground">{v.cve_id ?? '—'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-mono text-sm font-bold ${cvssColor(v.cvss_score)}`}>
                        {v.cvss_score?.toFixed(1) ?? '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {v.severity
                        ? <SeverityBadge severity={v.severity.charAt(0).toUpperCase() + v.severity.slice(1) as 'Critical' | 'High' | 'Medium' | 'Low'} />
                        : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground max-w-xs truncate">{v.description ?? '—'}</td>
                    <td className="px-4 py-3 text-xs font-mono text-center">{v.affected_assets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default VulnerabilitiesPage;
