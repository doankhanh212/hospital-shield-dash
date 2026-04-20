import { useState } from 'react';
import { FileCode, Plus, Play, Pause, Pencil, Trash2, AlertTriangle, X } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import SeverityBadge from '@/components/widgets/SeverityBadge';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

interface RuleItem {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  enabled: boolean;
  matches: number;
  lastTriggered: string;
}

const seedRules: RuleItem[] = [
  { id: '1', name: 'IoT kết nối Internet', description: 'Phát hiện thiết bị IoT/IoMT kết nối ra ngoài mạng bệnh viện', severity: 'Critical', enabled: true, matches: 3, lastTriggered: '2026-04-08 14:28' },
  { id: '2', name: 'Thiết bị mới trên mạng', description: 'Cảnh báo khi phát hiện MAC address chưa từng thấy', severity: 'High', enabled: true, matches: 1, lastTriggered: '2026-04-08 13:45' },
  { id: '3', name: 'Quét port nội bộ', description: 'Phát hiện quét port trên hơn 100 host trong 5 phút', severity: 'Critical', enabled: true, matches: 1, lastTriggered: '2026-04-08 13:50' },
  { id: '4', name: 'DICOM ngoài giờ', description: 'Lưu lượng DICOM bất thường ngoài giờ làm việc (22h-6h)', severity: 'Medium', enabled: true, matches: 2, lastTriggered: '2026-04-07 22:15' },
  { id: '5', name: 'Đăng nhập thất bại', description: 'Hơn 3 lần đăng nhập thất bại trong 10 phút', severity: 'Low', enabled: false, matches: 0, lastTriggered: '—' },
  { id: '6', name: 'Firmware update bất thường', description: 'Thiết bị y tế cập nhật firmware ngoài lịch bảo trì', severity: 'High', enabled: true, matches: 1, lastTriggered: '2026-04-08 13:15' },
];

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

const AdminRulesPage = () => {
  const [rules, setRules] = useState<RuleItem[]>(seedRules);
  const [showForm, setShowForm] = useState(false);

  // Create form state
  const [formName, setFormName] = useState('');
  const [formSeverity, setFormSeverity] = useState<Severity>('Medium');
  const [formDesc, setFormDesc] = useState('');

  // Edit modal
  const [editRule, setEditRule] = useState<RuleItem | null>(null);
  const [editName, setEditName] = useState('');
  const [editSeverity, setEditSeverity] = useState<Severity>('Medium');
  const [editDesc, setEditDesc] = useState('');

  // Delete modal
  const [deleteRule, setDeleteRule] = useState<RuleItem | null>(null);

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  const resetForm = () => {
    setFormName('');
    setFormSeverity('Medium');
    setFormDesc('');
  };

  const handleCreate = () => {
    if (!formName.trim()) return;
    const newRule: RuleItem = {
      id: String(Date.now()),
      name: formName.trim(),
      description: formDesc.trim(),
      severity: formSeverity,
      enabled: true,
      matches: 0,
      lastTriggered: '—',
    };
    setRules(prev => [...prev, newRule]);
    resetForm();
    setShowForm(false);
  };

  const openEdit = (rule: RuleItem) => {
    setEditRule(rule);
    setEditName(rule.name);
    setEditSeverity(rule.severity);
    setEditDesc(rule.description);
  };

  const handleEditSave = () => {
    if (!editRule || !editName.trim()) return;
    setRules(prev => prev.map(r => r.id === editRule.id ? { ...r, name: editName.trim(), severity: editSeverity, description: editDesc.trim() } : r));
    setEditRule(null);
  };

  const handleDelete = () => {
    if (!deleteRule) return;
    setRules(prev => prev.filter(r => r.id !== deleteRule.id));
    setDeleteRule(null);
  };

  const inputClass = "rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors";

  return (
    <div className="space-y-6">
      {/* Edit modal */}
      {editRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">Chỉnh sửa rule</h2>
              <button onClick={() => setEditRule(null)} className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors"><X size={16} /></button>
            </div>
            <div className="space-y-4 p-5">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">Tên rule</label>
                <input value={editName} onChange={e => setEditName(e.target.value)} className={inputClass + ' w-full'} />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">Mức độ</label>
                <select value={editSeverity} onChange={e => setEditSeverity(e.target.value as Severity)} className={inputClass + ' w-full'}>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">Mô tả</label>
                <textarea value={editDesc} onChange={e => setEditDesc(e.target.value)} className={inputClass + ' w-full h-20 resize-none'} />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button onClick={() => setEditRule(null)} className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors">Hủy</button>
                <button onClick={handleEditSave} disabled={!editName.trim()} className="rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors">Lưu</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm modal */}
      {deleteRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-sm rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">Xóa rule</h2>
              <button onClick={() => setDeleteRule(null)} className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors"><X size={16} /></button>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-3">
                <AlertTriangle size={16} className="mt-0.5 shrink-0 text-destructive" />
                <div className="text-xs text-foreground">
                  <p className="font-medium text-destructive mb-1">Xác nhận xóa</p>
                  <p className="text-muted-foreground">Rule <span className="font-medium text-foreground">{deleteRule.name}</span> sẽ bị xóa vĩnh viễn.</p>
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <button onClick={() => setDeleteRule(null)} className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors">Hủy</button>
                <button onClick={handleDelete} className="rounded-lg bg-destructive px-4 py-2 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 transition-colors">Xóa</button>
              </div>
            </div>
          </div>
        </div>
      )}

      <PageHeader
        title="Rule Detection"
        description={`${rules.length} quy tắc phát hiện mối đe dọa`}
        actions={
          <button onClick={() => { setShowForm(!showForm); resetForm(); }} className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm">
            <Plus size={14} />
            Thêm rule
          </button>
        }
      />

      {showForm && (
        <div className="rounded-lg border border-primary/20 bg-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-foreground">Tạo rule mới</h3>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-foreground">Tên rule <span className="text-destructive">*</span></label>
              <input value={formName} onChange={e => setFormName(e.target.value)} placeholder="Tên rule" className={inputClass + ' w-full'} />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-foreground">Mức độ</label>
              <select value={formSeverity} onChange={e => setFormSeverity(e.target.value as Severity)} className={inputClass + ' w-full'}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-foreground">Mô tả</label>
            <textarea value={formDesc} onChange={e => setFormDesc(e.target.value)} placeholder="Mô tả rule..." className={inputClass + ' w-full h-20 resize-none'} />
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} disabled={!formName.trim()} className="rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors">Lưu</button>
            <button onClick={() => { setShowForm(false); resetForm(); }} className="rounded-lg bg-secondary px-4 py-2 text-xs font-medium text-secondary-foreground hover:bg-accent transition-colors">Hủy</button>
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
                <button onClick={() => openEdit(rule)} className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors" title="Chỉnh sửa">
                  <Pencil size={13} />
                </button>
                <button onClick={() => setDeleteRule(rule)} className="rounded-md p-1.5 text-muted-foreground hover:bg-critical/10 hover:text-critical transition-colors" title="Xóa">
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
