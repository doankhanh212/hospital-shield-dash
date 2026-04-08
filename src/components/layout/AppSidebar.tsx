import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Monitor, Bug, Network, Bell, ScrollText, Settings, Shield
} from 'lucide-react';

const menuItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/assets', icon: Monitor, label: 'Tài sản' },
  { path: '/vulnerabilities', icon: Bug, label: 'Lỗ hổng' },
  { path: '/network', icon: Network, label: 'Hành vi mạng' },
  { path: '/alerts', icon: Bell, label: 'Cảnh báo' },
  { path: '/logs', icon: ScrollText, label: 'Nhật ký' },
  { path: '/settings', icon: Settings, label: 'Cài đặt' },
];

const AppSidebar = () => {
  const location = useLocation();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-60 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-16 items-center gap-2.5 border-b border-sidebar-border px-5">
        <Shield className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-sm font-bold text-sidebar-accent-foreground tracking-wide">HQG Security</h1>
          <p className="text-[10px] text-sidebar-foreground">Platform v2.1</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {menuItems.map(({ path, icon: Icon, label }) => {
          const isActive = path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);
          return (
            <NavLink
              key={path}
              to={path}
              className={`flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-all duration-150 ${
                isActive
                  ? 'bg-primary/10 text-primary'
                  : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
              }`}
            >
              <Icon className="h-4.5 w-4.5" size={18} />
              {label}
              {label === 'Cảnh báo' && (
                <span className="ml-auto flex h-5 w-5 items-center justify-center rounded-full bg-critical text-[10px] font-bold text-critical-foreground">
                  4
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>
      <div className="border-t border-sidebar-border p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-xs font-bold text-primary">
            AD
          </div>
          <div>
            <p className="text-xs font-medium text-sidebar-accent-foreground">Admin</p>
            <p className="text-[10px] text-sidebar-foreground">SOC Analyst</p>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default AppSidebar;
