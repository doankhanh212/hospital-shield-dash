import { useState } from 'react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import { vulnerabilities } from '@/data/mockData';
import { Bug } from 'lucide-react';

const severities = ['Tất cả', 'Critical', 'High', 'Medium', 'Low'] as const;

const VulnerabilitiesPage = () => {
  const [filter, setFilter] = useState<string>('Tất cả');

  const filtered = filter === 'Tất cả' ? vulnerabilities : vulnerabilities.filter(v => v.severity === filter);

  const counts = {
    Critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
    High: vulnerabilities.filter(v => v.severity === 'High').length,
    Medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
    Low: vulnerabilities.filter(v => v.severity === 'Low').length,
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-foreground">Quản lý lỗ hổng</h2>
        <p className="text-sm text-muted-foreground">Danh sách CVE ảnh hưởng đến thiết bị trong mạng</p>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(['Critical', 'High', 'Medium', 'Low'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setFilter(filter === sev ? 'Tất cả' : sev)}
            className={`rounded-lg border p-4 text-center transition-all hover:scale-[1.02] ${filter === sev ? 'ring-2 ring-primary' : ''} ${
              sev === 'Critical' ? 'border-critical/30 bg-critical/5' :
              sev === 'High' ? 'border-high/30 bg-high/5' :
              sev === 'Medium' ? 'border-medium/30 bg-medium/5' :
              'border-low/30 bg-low/5'
            }`}
          >
            <p className={`text-2xl font-bold ${sev === 'Critical' ? 'text-critical' : sev === 'High' ? 'text-high' : sev === 'Medium' ? 'text-medium' : 'text-low'}`}>
              {counts[sev]}
            </p>
            <p className="text-xs text-muted-foreground mt-1">{sev}</p>
          </button>
        ))}
      </div>

      {/* CVE List */}
      <div className="rounded-lg border border-border bg-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
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
              <tr key={v.cve} className="border-b border-border/50 transition-colors hover:bg-accent/50">
                <td className="px-4 py-3 font-mono text-xs font-semibold text-foreground flex items-center gap-2">
                  <Bug size={14} className="text-critical" />
                  {v.cve}
                </td>
                <td className="px-4 py-3">
                  <span className={`font-mono text-sm font-bold ${v.cvss >= 9 ? 'text-critical' : v.cvss >= 7 ? 'text-high' : v.cvss >= 4 ? 'text-medium' : 'text-low'}`}>
                    {v.cvss}
                  </span>
                </td>
                <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                <td className="px-4 py-3 text-xs text-muted-foreground max-w-xs">{v.description}</td>
                <td className="px-4 py-3 text-xs font-mono">{v.deviceCount}</td>
                <td className="px-4 py-3 text-xs text-muted-foreground">{v.published}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default VulnerabilitiesPage;
