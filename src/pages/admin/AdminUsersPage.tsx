import { useState } from 'react';
import { Users, Plus, Search, MoreHorizontal, Shield, Pencil, Trash2 } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';

const mockUsers = [
  { id: '1', name: 'Nguyễn Văn An', email: 'an.nguyen@hospital.local', role: 'admin', status: 'active', lastLogin: '2026-04-08 14:30' },
  { id: '2', name: 'Trần Thị Bình', email: 'binh.tran@hospital.local', role: 'analyst', status: 'active', lastLogin: '2026-04-08 13:15' },
  { id: '3', name: 'Lê Minh Cường', email: 'cuong.le@hospital.local', role: 'analyst', status: 'active', lastLogin: '2026-04-08 10:00' },
  { id: '4', name: 'Phạm Hồng Đào', email: 'dao.pham@hospital.local', role: 'viewer', status: 'inactive', lastLogin: '2026-04-01 09:00' },
  { id: '5', name: 'Hoàng Minh Đức', email: 'duc.hoang@hospital.local', role: 'analyst', status: 'active', lastLogin: '2026-04-07 16:45' },
];

const roleLabels: Record<string, { label: string; style: string }> = {
  admin: { label: 'Admin', style: 'bg-critical/10 text-critical border-critical/20' },
  analyst: { label: 'Analyst', style: 'bg-primary/10 text-primary border-primary/20' },
  viewer: { label: 'Viewer', style: 'bg-muted text-muted-foreground border-border' },
};

const AdminUsersPage = () => {
  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);

  const filtered = mockUsers.filter(u =>
    !search || u.name.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quản lý người dùng"
        description={`${mockUsers.length} tài khoản trong hệ thống`}
        actions={
          <button onClick={() => setShowForm(!showForm)} className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm">
            <Plus size={14} />
            Thêm người dùng
          </button>
        }
      />

      {showForm && (
        <div className="rounded-lg border border-primary/20 bg-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-foreground">Thêm người dùng mới</h3>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <input className="rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30" placeholder="Họ tên" />
            <input className="rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30" placeholder="Email" />
            <select className="rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30">
              <option>Chọn vai trò</option>
              <option>Admin</option>
              <option>Analyst</option>
              <option>Viewer</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button className="rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors">Lưu</button>
            <button onClick={() => setShowForm(false)} className="rounded-lg bg-secondary px-4 py-2 text-xs font-medium text-secondary-foreground hover:bg-accent transition-colors">Hủy</button>
          </div>
        </div>
      )}

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={15} />
        <input
          className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30"
          placeholder="Tìm kiếm người dùng..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3">Người dùng</th>
                <th className="px-4 py-3">Vai trò</th>
                <th className="px-4 py-3">Trạng thái</th>
                <th className="px-4 py-3">Đăng nhập cuối</th>
                <th className="px-4 py-3 text-right">Thao tác</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(user => (
                <tr key={user.id} className="border-b border-border/30 transition-colors hover:bg-accent/40">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-xs font-bold text-primary">
                        {user.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-foreground">{user.name}</p>
                        <p className="text-[11px] text-muted-foreground">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${roleLabels[user.role].style}`}>
                      {user.role === 'admin' && <Shield size={10} />}
                      {roleLabels[user.role].label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 text-[11px] ${user.status === 'active' ? 'text-success' : 'text-muted-foreground'}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${user.status === 'active' ? 'bg-success' : 'bg-muted-foreground'}`} />
                      {user.status === 'active' ? 'Hoạt động' : 'Vô hiệu'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[11px] text-muted-foreground font-mono">{user.lastLogin}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors">
                        <Pencil size={13} />
                      </button>
                      <button className="rounded-md p-1.5 text-muted-foreground hover:bg-critical/10 hover:text-critical transition-colors">
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AdminUsersPage;
