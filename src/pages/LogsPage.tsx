import { useState, useEffect } from 'react';
import { Search } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { TableSkeleton } from '@/components/widgets/Skeletons';

const logs = [
  { timestamp: '2026-04-08 14:35:12', level: 'INFO', source: 'Scanner', message: 'Hoàn tất quét mạng VLAN 10 - phát hiện 5 thiết bị' },
  { timestamp: '2026-04-08 14:30:05', level: 'WARNING', source: 'IDS', message: 'Phát hiện kết nối bất thường từ 10.0.2.15 đến 203.0.113.50' },
  { timestamp: '2026-04-08 14:28:33', level: 'ERROR', source: 'Firewall', message: 'Chặn kết nối từ 10.0.4.100 - port scan detected' },
  { timestamp: '2026-04-08 14:25:18', level: 'INFO', source: 'Asset Manager', message: 'Cập nhật thông tin thiết bị 10.0.1.20 - Philips CT Scanner' },
  { timestamp: '2026-04-08 13:50:42', level: 'CRITICAL', source: 'IDS', message: 'Phát hiện quét port từ 10.0.4.100 trên dải 10.0.0.0/16' },
  { timestamp: '2026-04-08 13:45:00', level: 'WARNING', source: 'DHCP', message: 'Thiết bị mới kết nối - MAC: 00:6F:7A:8B:9C:AD - IP: 10.0.4.100' },
  { timestamp: '2026-04-08 12:00:15', level: 'WARNING', source: 'Policy', message: 'Camera Hikvision kết nối ra internet - vi phạm chính sách' },
  { timestamp: '2026-04-08 10:30:00', level: 'INFO', source: 'Vuln Scanner', message: 'Phát hiện CVE-2024-1234 trên thiết bị 10.0.1.10' },
  { timestamp: '2026-04-08 10:00:22', level: 'INFO', source: 'Auth', message: 'Đăng nhập thành công - admin@hospital.local' },
  { timestamp: '2026-04-07 22:15:30', level: 'WARNING', source: 'Anomaly', message: 'Lưu lượng DICOM bất thường từ 10.0.1.20 ngoài giờ làm việc' },
  { timestamp: '2026-04-07 18:00:45', level: 'INFO', source: 'Auth', message: '5 lần đăng nhập thất bại vào Cisco switch 10.0.5.10' },
  { timestamp: '2026-04-07 16:30:10', level: 'INFO', source: 'System', message: 'Cập nhật cơ sở dữ liệu CVE - 234 bản ghi mới' },
];

const levelStyles: Record<string, string> = {
  INFO: 'text-info bg-info/10',
  WARNING: 'text-warning bg-warning/10',
  ERROR: 'text-high bg-high/10',
  CRITICAL: 'text-critical bg-critical/10',
};

const LogsPage = () => {
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 500);
    return () => clearTimeout(t);
  }, []);

  const filtered = logs.filter(l =>
    !search || l.message.toLowerCase().includes(search.toLowerCase()) || l.source.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Nhật ký hệ thống" description={`${logs.length} sự kiện gần đây`} />

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={15} />
        <input
          className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
          placeholder="Tìm kiếm nhật ký..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {loading ? (
        <TableSkeleton rows={10} cols={4} />
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-left text-[10px] font-medium uppercase tracking-wider text-muted-foreground font-sans">
                  <th className="px-4 py-3">Thời gian</th>
                  <th className="px-4 py-3">Level</th>
                  <th className="px-4 py-3">Nguồn</th>
                  <th className="px-4 py-3">Nội dung</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log, i) => (
                  <tr key={i} className="border-b border-border/30 hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-2.5 text-muted-foreground whitespace-nowrap">{log.timestamp}</td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-bold ${levelStyles[log.level]}`}>
                        {log.level}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-foreground font-sans text-xs">{log.source}</td>
                    <td className="px-4 py-2.5 text-muted-foreground font-sans text-xs">{log.message}</td>
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

export default LogsPage;
