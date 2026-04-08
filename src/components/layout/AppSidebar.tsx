import { NavLink, useLocation } from 'react-router-dom';
import { Sun, Moon, ChevronDown } from 'lucide-react';
import {
  LayoutDashboard, Monitor, Bug, Network, Bell, ScrollText, Settings, Shield,
  Users, ShieldCheck, Cog, FileCode, Plug
} from 'lucide-react';
import { useTheme } from '@/hooks/useTheme';
import { useState } from 'react';

const mainMenu = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/assets', icon: Monitor, label: 'Tài sản' },
  { path: '/vulnerabilities', icon: Bug, label: 'Lỗ hổng' },
  { path: '/network', icon: Network, label: 'Hành vi mạng' },
  { path: '/alerts', icon: Bell, label: 'Cảnh báo', badge: 4 },
  { path: '/logs', icon: ScrollText, label: 'Nhật ký' },
];

const adminMenu = [
  { path: '/admin/users', icon: Users, label: 'Người dùng' },
  { path: '/admin/roles', icon: ShieldCheck, label: 'Phân quyền' },
  { path: '/admin/system', icon: Cog, label: 'Cấu hình hệ thống' },
  { path: '/admin/rules', icon: FileCode, label: 'Rule Detection' },
  { path: '/admin/integrations', icon: Plug, label: 'Tích hợp' },
  { path: '/settings', icon: Settings, label: 'Cài đặt' },
];

const AppSidebar = () => {
  const location = useLocation();
  const { theme, toggleTheme } = useTheme();
  const [adminOpen, setAdminOpen] = useState(location.pathname.startsWith('/admin') || location.pathname === '/settings');

  const isActive = (path: string) =>
    path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);

  const MenuItem = ({ path, icon: Icon, label, badge }: { path: string; icon: React.ElementType; label: string; badge?: number }) => (
    <NavLink
      to={path}
      className={`group flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] font-medium transition-all duration-150 ${
        isActive(path)
          ? 'bg-primary/10 text-primary shadow-sm'
          : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
      }`}
    >
      <Icon size={17} className={isActive(path) ? 'text-primary' : 'text-sidebar-foreground group-hover:text-sidebar-accent-foreground'} />
      <span className="truncate">{label}</span>
      {badge && (
        <span className="ml-auto flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-critical px-1 text-[10px] font-bold text-critical-foreground">
          {badge}
        </span>
      )}
    </NavLink>
  );

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-[232px] flex-col border-r border-sidebar-border bg-sidebar">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 border-b border-sidebar-border px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
          <Shield className="h-[18px] w-[18px] text-primary" />
        </div>
        <div className="min-w-0">
          <h1 className="text-[13px] font-bold text-sidebar-accent-foreground tracking-wide leading-tight">HQG Security</h1>
          <p className="text-[10px] text-sidebar-foreground leading-tight">Platform v2.1</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-3 space-y-5">
        {/* Main */}
        <div className="space-y-0.5">
          <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-wider text-sidebar-foreground/60">Giám sát</p>
          {mainMenu.map(item => <MenuItem key={item.path} {...item} />)}
        </div>

        {/* Admin */}
        <div className="space-y-0.5">
          <button
            onClick={() => setAdminOpen(!adminOpen)}
            className="mb-2 flex w-full items-center justify-between px-3 text-[10px] font-semibold uppercase tracking-wider text-sidebar-foreground/60 hover:text-sidebar-foreground transition-colors"
          >
            Quản trị
            <ChevronDown size={12} className={`transition-transform duration-200 ${adminOpen ? 'rotate-180' : ''}`} />
          </button>
          {adminOpen && adminMenu.map(item => <MenuItem key={item.path} {...item} />)}
        </div>
      </nav>

      {/* Footer */}
      <div className="border-t border-sidebar-border p-3 space-y-3">
        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-[13px] text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          <span>{theme === 'dark' ? 'Chế độ sáng' : 'Chế độ tối'}</span>
        </button>

        {/* User */}
        <div className="flex items-center gap-2.5 rounded-lg bg-sidebar-accent/50 px-3 py-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary text-[10px] font-bold text-primary-foreground">
            AD
          </div>
          <div className="min-w-0">
            <p className="text-[12px] font-medium text-sidebar-accent-foreground truncate">Admin</p>
            <p className="text-[10px] text-sidebar-foreground truncate">SOC Analyst</p>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default AppSidebar;
