import { useState } from 'react';
import { Plug, CheckCircle2, XCircle, RefreshCw, ExternalLink } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';

const integrations = [
  {
    id: 'zeek',
    name: 'Zeek (Bro)',
    description: 'Giám sát lưu lượng mạng, phân tích giao thức',
    status: 'connected' as const,
    version: '6.0.3',
    host: '10.0.5.20:47760',
    lastSync: '2026-04-08 14:30',
    config: { logPath: '/opt/zeek/logs/current', interface: 'eth0' },
  },
  {
    id: 'postgres',
    name: 'PostgreSQL',
    description: 'Cơ sở dữ liệu chính lưu trữ tài sản và cảnh báo',
    status: 'connected' as const,
    version: '16.2',
    host: '10.0.5.30:5432',
    lastSync: '2026-04-08 14:35',
    config: { database: 'hqg_security', schema: 'public' },
  },
  {
    id: 'suricata',
    name: 'Suricata IDS',
    description: 'Hệ thống phát hiện xâm nhập dựa trên signature',
    status: 'disconnected' as const,
    version: '—',
    host: '—',
    lastSync: '—',
    config: {},
  },
  {
    id: 'syslog',
    name: 'Syslog Server',
    description: 'Thu thập nhật ký từ các thiết bị mạng',
    status: 'connected' as const,
    version: 'rsyslog 8.2312',
    host: '10.0.5.25:514',
    lastSync: '2026-04-08 14:33',
    config: { protocol: 'UDP', facility: 'local0' },
  },
  {
    id: 'elasticsearch',
    name: 'Elasticsearch',
    description: 'Lưu trữ và tìm kiếm nhật ký phân tán',
    status: 'error' as const,
    version: '8.12',
    host: '10.0.5.40:9200',
    lastSync: '2026-04-07 18:00',
    config: { index: 'hqg-logs-*', error: 'Connection timeout' },
  },
];

const statusConfig = {
  connected: { label: 'Đã kết nối', icon: CheckCircle2, style: 'text-success bg-success/10' },
  disconnected: { label: 'Chưa kết nối', icon: XCircle, style: 'text-muted-foreground bg-muted' },
  error: { label: 'Lỗi kết nối', icon: XCircle, style: 'text-critical bg-critical/10' },
};

const AdminIntegrationsPage = () => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tích hợp"
        description="Quản lý kết nối với các hệ thống bên ngoài"
      />

      <div className="space-y-3">
        {integrations.map(int => {
          const cfg = statusConfig[int.status];
          const StatusIcon = cfg.icon;
          const expanded = expandedId === int.id;

          return (
            <div key={int.id} className="rounded-lg border border-border bg-card overflow-hidden transition-all">
              <div
                className="flex items-center justify-between p-4 cursor-pointer hover:bg-accent/20 transition-colors"
                onClick={() => setExpandedId(expanded ? null : int.id)}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <Plug size={18} className="text-primary" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-foreground">{int.name}</span>
                      <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ${cfg.style}`}>
                        <StatusIcon size={10} />
                        {cfg.label}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{int.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {int.status === 'connected' && (
                    <button className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors" title="Đồng bộ lại">
                      <RefreshCw size={14} />
                    </button>
                  )}
                </div>
              </div>

              {expanded && (
                <div className="border-t border-border bg-muted/20 p-4 space-y-3">
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <div>
                      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Host</p>
                      <p className="mt-0.5 text-xs font-mono text-foreground">{int.host}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Phiên bản</p>
                      <p className="mt-0.5 text-xs text-foreground">{int.version}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Đồng bộ cuối</p>
                      <p className="mt-0.5 text-xs font-mono text-foreground">{int.lastSync}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Cấu hình</p>
                      <p className="mt-0.5 text-xs font-mono text-foreground">
                        {Object.entries(int.config).map(([k, v]) => `${k}: ${v}`).join(', ') || '—'}
                      </p>
                    </div>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <button className="rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors">Chỉnh sửa</button>
                    {int.status !== 'connected' && (
                      <button className="rounded-lg bg-success px-3 py-1.5 text-xs font-medium text-success-foreground hover:bg-success/90 transition-colors">Kết nối</button>
                    )}
                    {int.status === 'connected' && (
                      <button className="rounded-lg bg-secondary px-3 py-1.5 text-xs font-medium text-secondary-foreground hover:bg-accent transition-colors">Ngắt kết nối</button>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default AdminIntegrationsPage;
