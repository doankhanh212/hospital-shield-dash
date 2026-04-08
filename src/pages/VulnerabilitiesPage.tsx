import { useState, useEffect } from 'react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import PageHeader from '@/components/widgets/PageHeader';
import { TableSkeleton, StatCardsSkeleton } from '@/components/widgets/Skeletons';
import { vulnerabilities } from '@/data/mockData';
import { Bug } from 'lucide-react';

const VulnerabilitiesPage = () => {
  const [filter, setFilter] = useState<string>('Tất cả');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 600);
    return () => clearTimeout(t);
  }, []);

  const filtered = filter === 'Tất cả' ? vulnerabilities : vulnerabilities.filter(v => v.severity === filter);

  const counts = {
    Critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
    High: vulnerabilities.filter(v => v.severity === 'High').length,
    Medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
    Low: vulnerabilities.filter(v => v.severity === 'Low').length,
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Quản lý lỗ hổng" description="Danh sách CVE ảnh hưởng đến thiết bị trong mạng" />
        <StatCardsSkeleton />
        <TableSkeleton rows={7} cols={6} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Quản lý lỗ hổng" description={`${vulnerabilities.length} lỗ hổng đã phát hiện`} />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(['Critical', 'High', 'Medium', 'Low'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setFilter(filter === sev ? 'Tất cả' : sev)}
            className={`rounded-lg border p-4 text-center transition-all duration-150 hover:scale-[1.01] ${filter === sev ? 'ring-2 ring-primary ring-offset-1 ring-offset-background' : ''} ${
              sev === 'Critical' ? 'border-critical/20 bg-card' :
              sev === 'High' ? 'border-high/20 bg-card' :
              sev === 'Medium' ? 'border-medium/20 bg-card' :
              'border-low/20 bg-card'
            }`}
          >
            <p className={`text-2xl font-bold ${sev === 'Critical' ? 'text-critical' : sev === 'High' ? 'text-high' : sev === 'Medium' ? 'text-medium' : 'text-low'}`}>
              {counts[sev]}
            </p>
            <p className="text-[11px] text-muted-foreground mt-1 font-medium">{sev}</p>
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3">CVE</th>
                <th className="px-4 py-3">CVSS</th>
                <th className="px-4 py-3">Mức độ</th>
                <th className="px-4 py-3">Mô tả</th>
                <th className="px-4 py-3">Thiết bị</th>
                <th className="px-4 py-3">Công bố</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(v => (
                <tr key={v.cve} className="border-b border-border/30 transition-colors hover:bg-accent/40">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Bug size={13} className="text-muted-foreground" />
                      <span className="font-mono text-xs font-semibold text-foreground">{v.cve}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-mono text-sm font-bold ${v.cvss >= 9 ? 'text-critical' : v.cvss >= 7 ? 'text-high' : v.cvss >= 4 ? 'text-medium' : 'text-low'}`}>
                      {v.cvss}
                    </span>
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                  <td className="px-4 py-3 text-xs text-muted-foreground max-w-xs">{v.description}</td>
                  <td className="px-4 py-3 text-xs font-mono text-center">{v.deviceCount}</td>
                  <td className="px-4 py-3 text-[11px] text-muted-foreground">{v.published}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default VulnerabilitiesPage;
