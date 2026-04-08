import { Outlet } from 'react-router-dom';
import AppSidebar from './AppSidebar';
import { Activity, Clock } from 'lucide-react';
import { useEffect, useState } from 'react';

const TopBar = () => {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="sticky top-0 z-30 flex h-12 items-center justify-between border-b border-border bg-background/80 backdrop-blur-sm px-6">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Activity size={13} className="text-success animate-pulse-glow" />
        <span>Hệ thống hoạt động bình thường</span>
      </div>
      <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
        <Clock size={13} />
        {time.toLocaleString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit', day: '2-digit', month: '2-digit', year: 'numeric' })}
      </div>
    </header>
  );
};

const DashboardLayout = () => {
  return (
    <div className="flex min-h-screen bg-background">
      <AppSidebar />
      <div className="ml-[232px] flex-1 flex flex-col min-h-screen">
        <TopBar />
        <main className="flex-1 overflow-auto">
          <div className="p-6 max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
