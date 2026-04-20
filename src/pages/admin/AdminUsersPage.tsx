import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Search, Shield, Pencil, Trash2, Loader2, AlertCircle, X } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { TableSkeleton } from '@/components/widgets/Skeletons';
import { api, AdminUser } from '@/lib/api';
import { format } from 'date-fns';

type Role = 'admin' | 'analyst';

const roleLabels: Record<string, { label: string; style: string }> = {
  admin: { label: 'Admin', style: 'bg-critical/10 text-critical border-critical/20' },
  analyst: { label: 'Analyst', style: 'bg-primary/10 text-primary border-primary/20' },
};

const inputClass =
  'rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors';

const formatDate = (iso: string | null) => {
  if (!iso) return '—';
  try {
    return format(new Date(iso), 'yyyy-MM-dd HH:mm');
  } catch {
    return '—';
  }
};

const AdminUsersPage = () => {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);

  // Create form
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formRole, setFormRole] = useState<Role>('analyst');
  const [formError, setFormError] = useState<string | null>(null);

  // Edit modal
  const [editUser, setEditUser] = useState<AdminUser | null>(null);
  const [editRole, setEditRole] = useState<Role>('analyst');
  const [editActive, setEditActive] = useState(true);
  const [editPassword, setEditPassword] = useState('');
  const [editError, setEditError] = useState<string | null>(null);

  // Delete modal
  const [deleteTarget, setDeleteTarget] = useState<AdminUser | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const { data: users = [], isLoading, isError, error } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.listUsers(),
  });

  const createMut = useMutation({
    mutationFn: () =>
      api.createUser({ username: formUsername.trim(), password: formPassword, role: formRole }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] });
      resetForm();
      setShowForm(false);
    },
    onError: (e: unknown) =>
      setFormError(e instanceof Error ? e.message : 'Không thể tạo người dùng'),
  });

  const updateMut = useMutation({
    mutationFn: (args: { id: string; body: Parameters<typeof api.updateUser>[1] }) =>
      api.updateUser(args.id, args.body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] });
      setEditUser(null);
      setEditPassword('');
    },
    onError: (e: unknown) =>
      setEditError(e instanceof Error ? e.message : 'Không thể cập nhật người dùng'),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] });
      setDeleteTarget(null);
    },
    onError: (e: unknown) =>
      setDeleteError(e instanceof Error ? e.message : 'Không thể xóa người dùng'),
  });

  const resetForm = () => {
    setFormUsername('');
    setFormPassword('');
    setFormRole('analyst');
    setFormError(null);
  };

  const filtered = users.filter(u => !search || u.username.toLowerCase().includes(search.toLowerCase()));

  const handleCreate = () => {
    if (!formUsername.trim() || formPassword.length < 10) {
      setFormError('Tên đăng nhập bắt buộc, mật khẩu tối thiểu 10 ký tự');
      return;
    }
    setFormError(null);
    createMut.mutate();
  };

  const openEdit = (user: AdminUser) => {
    setEditUser(user);
    setEditRole(user.role);
    setEditActive(user.is_active);
    setEditPassword('');
    setEditError(null);
  };

  const handleEditSave = () => {
    if (!editUser) return;
    const body: Parameters<typeof api.updateUser>[1] = {};
    if (editRole !== editUser.role) body.role = editRole;
    if (editActive !== editUser.is_active) body.is_active = editActive;
    if (editPassword.trim()) {
      if (editPassword.length < 10) {
        setEditError('Mật khẩu mới tối thiểu 10 ký tự');
        return;
      }
      body.password = editPassword;
    }
    if (Object.keys(body).length === 0) {
      setEditUser(null);
      return;
    }
    setEditError(null);
    updateMut.mutate({ id: editUser.id, body });
  };

  const handleDelete = () => {
    if (!deleteTarget) return;
    setDeleteError(null);
    deleteMut.mutate(deleteTarget.id);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quản lý người dùng"
        description={`${users.length} tài khoản trong hệ thống`}
        actions={
          <button
            onClick={() => { setShowForm(v => !v); resetForm(); }}
            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
          >
            <Plus size={14} />
            Thêm người dùng
          </button>
        }
      />

      {showForm && (
        <div className="rounded-lg border border-primary/20 bg-card p-5 space-y-4">
          <h3 className="text-sm font-semibold text-foreground">Thêm người dùng mới</h3>
          {formError && (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2.5 text-xs text-destructive">
              <AlertCircle size={13} /> {formError}
            </div>
          )}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-foreground">
                Tên đăng nhập <span className="text-destructive">*</span>
              </label>
              <input
                value={formUsername}
                onChange={e => setFormUsername(e.target.value)}
                placeholder="username"
                className={inputClass + ' w-full'}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-foreground">
                Mật khẩu (≥10 ký tự) <span className="text-destructive">*</span>
              </label>
              <input
                type="password"
                value={formPassword}
                onChange={e => setFormPassword(e.target.value)}
                placeholder="••••••••••"
                className={inputClass + ' w-full'}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-foreground">Vai trò</label>
              <select
                value={formRole}
                onChange={e => setFormRole(e.target.value as Role)}
                className={inputClass + ' w-full'}
              >
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              disabled={createMut.isPending || !formUsername.trim() || formPassword.length < 10}
              className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {createMut.isPending && <Loader2 size={13} className="animate-spin" />}
              Tạo tài khoản
            </button>
            <button
              onClick={() => { setShowForm(false); resetForm(); }}
              className="rounded-lg bg-secondary px-4 py-2 text-xs font-medium text-secondary-foreground hover:bg-accent transition-colors"
            >
              Hủy
            </button>
          </div>
        </div>
      )}

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={15} />
        <input
          className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30"
          placeholder="Tìm kiếm theo tên đăng nhập..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {isLoading ? (
        <TableSkeleton rows={5} cols={5} />
      ) : isError ? (
        <div className="flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <AlertCircle size={16} />
          <span>Lỗi tải danh sách: {error instanceof Error ? error.message : 'Unknown'}</span>
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-3">Người dùng</th>
                  <th className="px-4 py-3">Vai trò</th>
                  <th className="px-4 py-3">Trạng thái</th>
                  <th className="px-4 py-3">Tạo lúc</th>
                  <th className="px-4 py-3 text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-xs text-muted-foreground">
                      Không tìm thấy người dùng nào
                    </td>
                  </tr>
                ) : (
                  filtered.map(user => (
                    <tr key={user.id} className="border-b border-border/30 transition-colors hover:bg-accent/40">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-xs font-bold text-primary uppercase">
                            {user.username.slice(0, 2)}
                          </div>
                          <div>
                            <p className="text-sm font-medium text-foreground">{user.username}</p>
                            <p className="text-[11px] text-muted-foreground font-mono">{user.id.slice(0, 8)}…</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${
                            roleLabels[user.role]?.style ?? roleLabels.analyst.style
                          }`}
                        >
                          {user.role === 'admin' && <Shield size={10} />}
                          {roleLabels[user.role]?.label ?? user.role}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1.5 text-[11px] ${
                            user.is_active ? 'text-success' : 'text-muted-foreground'
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              user.is_active ? 'bg-success' : 'bg-muted-foreground'
                            }`}
                          />
                          {user.is_active ? 'Hoạt động' : 'Vô hiệu'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[11px] text-muted-foreground font-mono">
                        {formatDate(user.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => openEdit(user)}
                            className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                            title="Chỉnh sửa"
                          >
                            <Pencil size={13} />
                          </button>
                          <button
                            onClick={() => { setDeleteTarget(user); setDeleteError(null); }}
                            className="rounded-md p-1.5 text-muted-foreground hover:bg-critical/10 hover:text-critical transition-colors"
                            title="Xóa"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">
                Chỉnh sửa: <span className="font-mono">{editUser.username}</span>
              </h2>
              <button
                onClick={() => setEditUser(null)}
                className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
              >
                <X size={16} />
              </button>
            </div>
            <div className="space-y-4 p-5">
              {editError && (
                <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  <AlertCircle size={13} /> {editError}
                </div>
              )}
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">Vai trò</label>
                <select
                  value={editRole}
                  onChange={e => setEditRole(e.target.value as Role)}
                  className={inputClass + ' w-full'}
                >
                  <option value="admin">Admin</option>
                  <option value="analyst">Analyst</option>
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">Trạng thái</label>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setEditActive(true)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                      editActive
                        ? 'border-success/50 bg-success/10 text-success'
                        : 'border-border text-muted-foreground hover:bg-accent'
                    }`}
                  >
                    Hoạt động
                  </button>
                  <button
                    onClick={() => setEditActive(false)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                      !editActive
                        ? 'border-border bg-muted text-foreground'
                        : 'border-border text-muted-foreground hover:bg-accent'
                    }`}
                  >
                    Vô hiệu
                  </button>
                </div>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">
                  Đặt lại mật khẩu (tùy chọn, ≥10 ký tự)
                </label>
                <input
                  type="password"
                  value={editPassword}
                  onChange={e => setEditPassword(e.target.value)}
                  placeholder="Để trống nếu không đổi"
                  className={inputClass + ' w-full'}
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  onClick={() => setEditUser(null)}
                  className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors"
                >
                  Hủy
                </button>
                <button
                  onClick={handleEditSave}
                  disabled={updateMut.isPending}
                  className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  {updateMut.isPending && <Loader2 size={13} className="animate-spin" />}
                  Lưu
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-sm rounded-xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">Xóa người dùng</h2>
              <button
                onClick={() => setDeleteTarget(null)}
                className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors"
              >
                <X size={16} />
              </button>
            </div>
            <div className="p-5 space-y-4">
              {deleteError && (
                <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  <AlertCircle size={13} /> {deleteError}
                </div>
              )}
              <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-3">
                <AlertCircle size={16} className="mt-0.5 shrink-0 text-destructive" />
                <div className="text-xs text-foreground">
                  <p className="font-medium text-destructive mb-1">Xác nhận xóa</p>
                  <p className="text-muted-foreground">
                    Tài khoản <span className="font-medium text-foreground font-mono">{deleteTarget.username}</span>{' '}
                    sẽ bị xóa vĩnh viễn.
                  </p>
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setDeleteTarget(null)}
                  className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors"
                >
                  Hủy
                </button>
                <button
                  onClick={handleDelete}
                  disabled={deleteMut.isPending}
                  className="flex items-center gap-2 rounded-lg bg-destructive px-4 py-2 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50 transition-colors"
                >
                  {deleteMut.isPending && <Loader2 size={13} className="animate-spin" />}
                  Xóa
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminUsersPage;
