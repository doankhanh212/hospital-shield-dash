import { ShieldCheck, Check, X } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';

const permissions = [
  { module: 'Dashboard', admin: true, analyst: true, viewer: true },
  { module: 'Tài sản — Xem', admin: true, analyst: true, viewer: true },
  { module: 'Tài sản — Chỉnh sửa', admin: true, analyst: true, viewer: false },
  { module: 'Lỗ hổng — Xem', admin: true, analyst: true, viewer: true },
  { module: 'Lỗ hổng — Quản lý', admin: true, analyst: false, viewer: false },
  { module: 'Hành vi mạng', admin: true, analyst: true, viewer: true },
  { module: 'Cảnh báo — Xem', admin: true, analyst: true, viewer: true },
  { module: 'Cảnh báo — Xử lý', admin: true, analyst: true, viewer: false },
  { module: 'Nhật ký', admin: true, analyst: true, viewer: false },
  { module: 'Quản lý người dùng', admin: true, analyst: false, viewer: false },
  { module: 'Phân quyền', admin: true, analyst: false, viewer: false },
  { module: 'Cấu hình hệ thống', admin: true, analyst: false, viewer: false },
  { module: 'Rule Detection', admin: true, analyst: true, viewer: false },
  { module: 'Tích hợp', admin: true, analyst: false, viewer: false },
  { module: 'Cài đặt', admin: true, analyst: false, viewer: false },
];

const PermIcon = ({ allowed }: { allowed: boolean }) => allowed
  ? <Check size={14} className="text-success" />
  : <X size={14} className="text-muted-foreground/40" />;

const AdminRolesPage = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Phân quyền"
        description="Ma trận quyền truy cập theo vai trò"
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 mb-2">
        {[
          { role: 'Admin', desc: 'Toàn quyền quản trị hệ thống', color: 'border-critical/20 bg-critical/5' },
          { role: 'Analyst', desc: 'Phân tích, xử lý cảnh báo, quản lý rule', color: 'border-primary/20 bg-primary/5' },
          { role: 'Viewer', desc: 'Chỉ xem dashboard và báo cáo', color: 'border-border bg-muted/30' },
        ].map(r => (
          <div key={r.role} className={`rounded-lg border p-4 ${r.color}`}>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck size={15} className={r.role === 'Admin' ? 'text-critical' : r.role === 'Analyst' ? 'text-primary' : 'text-muted-foreground'} />
              <span className="text-sm font-semibold text-foreground">{r.role}</span>
            </div>
            <p className="text-[11px] text-muted-foreground">{r.desc}</p>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3">Chức năng</th>
                <th className="px-4 py-3 text-center">Admin</th>
                <th className="px-4 py-3 text-center">Analyst</th>
                <th className="px-4 py-3 text-center">Viewer</th>
              </tr>
            </thead>
            <tbody>
              {permissions.map((p, i) => (
                <tr key={i} className="border-b border-border/30 transition-colors hover:bg-accent/40">
                  <td className="px-4 py-2.5 text-xs text-foreground">{p.module}</td>
                  <td className="px-4 py-2.5 text-center"><PermIcon allowed={p.admin} /></td>
                  <td className="px-4 py-2.5 text-center"><PermIcon allowed={p.analyst} /></td>
                  <td className="px-4 py-2.5 text-center"><PermIcon allowed={p.viewer} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AdminRolesPage;
