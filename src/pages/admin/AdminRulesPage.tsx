import { useState } from 'react';
import { FileCode, Plus, Play, Pause, Pencil, Trash2, AlertTriangle } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import SeverityBadge from '@/components/widgets/SeverityBadge';

const mockRules = [
  { id: '1', name: 'IoT kết nối Internet', description: 'Phát hiện thiết bị IoT/IoMT kết nối ra ngoài mạng bệnh viện', severity: 'Critical' as const, enabled: true, matches: 3, lastTriggered: '2026-04-08 14:28' },
  { id: '2', name: 'Thiết bị mới trên mạng', description: 'Cảnh báo khi phát hiện MAC address chưa từng thấy', severity: 'High' as const, enabled: true, matches: 1, lastTriggered: '2026-04-08 13:45' },
  { id: '3', name: 'Quét port nội bộ', description: 'Phát hiện quét port trên hơn 100 host trong 5 phút', severity: 'Critical' as const, enabled: true, matches: 1, lastTriggered: '2026-04-08 13:50' },
  { id: '4', name: 'DICOM ngoài giờ', description: 'Lưu lượng DICOM bất thường ngoài giờ làm việc (22h-6h)', severity: 'Medium' as const, enabled: true, matches: 2, lastTriggered: '2026-04-07 22:15' },
  { id: '5', name: 'Đăng nhập thất bại', description: 'Hơn 3 lần đăng nhập thất bại trong 10 phút', severity: 'Low' as const, enabled: false, matches: 0, lastTriggered: '—' },
  { id: '6', name: 'Firmware update bất thường', description: 'Thiết bị y tế cập nhật firmware ngoài lịch bảo trì', severity: 'High' as const, enabled: true, matches: 1, lastTriggered: '2026-04-08 13:15' },
];

const AdminRulesPage = () => {
  const [rules, setRules] = useState(mockRules);
  const [showForm, setShowForm] = useState(false);

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Rule Detection"
        description="Quản lý các quy tắc phát hiện mối đe dọa"
        actions={
          <button onClick={() => setShowForm(!showForm)} className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm">
            <Plus size={14} />
            Thêm rule
          </button>
        }
      />

      {showForm && (
        <div className="rounded-lg border border-primary/20 bg-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-foreground">Tạo rule mới</h3>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <input className="rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30" placeholder="Tên rule" />
            <select className="rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30">
              <option>Mức độ: Critical</option>
              <option>Mức độ: High</option>
              <option>Mức độ: Medium</option>
              <option>Mức độ: Low</option>
            </select>
          </div>
          <textarea className="w-full rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 h-20 resize-none" placeholder="Mô tả rule..." />
          <div className="flex gap-2">
            <button className="rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors">Lưu</button>
            <button onClick={() => setShowForm(false)} className="rounded-lg bg-secondary px-4 py-2 text-xs font-medium text-secondary-foreground hover:bg-accent transition-colors">Hủy</button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {rules.map(rule => (
          <div key={rule.id} className={`rounded-lg border bg-card p-4 transition-all hover:bg-accent/20 ${rule.enabled ? 'border-border' : 'border-border/50 opacity-60'}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3 min-w-0 flex-1">
                <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${rule.enabled ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}>
                  <FileCode size={15} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-semibold text-foreground">{rule.name}</span>
                    <SeverityBadge severity={rule.severity} />
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{rule.description}</p>
                  <div className="mt-2 flex items-center gap-4 text-[11px] text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <AlertTriangle size={10} />
                      {rule.matches} lần kích hoạt
                    </span>
                    <span>Lần cuối: {rule.lastTriggered}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => toggleRule(rule.id)}
                  className={`rounded-md p-1.5 transition-colors ${rule.enabled ? 'text-success hover:bg-success/10' : 'text-muted-foreground hover:bg-accent'}`}
                  title={rule.enabled ? 'Tắt rule' : 'Bật rule'}
                >
                  {rule.enabled ? <Pause size={13} /> : <Play size={13} />}
                </button>
                <button className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors">
                  <Pencil size={13} />
                </button>
                <button className="rounded-md p-1.5 text-muted-foreground hover:bg-critical/10 hover:text-critical transition-colors">
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AdminRulesPage;
