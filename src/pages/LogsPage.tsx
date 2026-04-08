import { ScrollText } from 'lucide-react';

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
  INFO: 'text-info',
  WARNING: 'text-warning',
  ERROR: 'text-high',
  CRITICAL: 'text-critical',
};

const LogsPage = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-foreground">Nhật ký hệ thống</h2>
        <p className="text-sm text-muted-foreground">Lịch sử hoạt động và sự kiện hệ thống</p>
      </div>

      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-4 py-3">Thời gian</th>
                <th className="px-4 py-3">Level</th>
                <th className="px-4 py-3">Nguồn</th>
                <th className="px-4 py-3">Nội dung</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, i) => (
                <tr key={i} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-2.5 text-muted-foreground whitespace-nowrap">{log.timestamp}</td>
                  <td className={`px-4 py-2.5 font-semibold ${levelStyles[log.level]}`}>{log.level}</td>
                  <td className="px-4 py-2.5 text-foreground">{log.source}</td>
                  <td className="px-4 py-2.5 text-muted-foreground font-sans">{log.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LogsPage;
