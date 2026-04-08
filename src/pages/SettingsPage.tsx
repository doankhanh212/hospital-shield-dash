import { Settings, Shield, Bell, Network, Database, Info } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { useState } from 'react';

const SettingsPage = () => {
  const Toggle = ({ label, description, defaultOn = false }: { label: string; description: string; defaultOn?: boolean }) => {
    const [on, setOn] = useState(defaultOn);
    return (
      <div className="flex items-center justify-between py-3 border-b border-border/30 last:border-0">
        <div>
          <p className="text-sm text-foreground">{label}</p>
          <p className="text-[11px] text-muted-foreground">{description}</p>
        </div>
        <button
          onClick={() => setOn(!on)}
          className={`relative h-6 w-11 rounded-full transition-colors ${on ? 'bg-primary' : 'bg-muted'}`}
        >
          <div className={`absolute top-0.5 h-5 w-5 rounded-full bg-card shadow-sm transition-transform ${on ? 'translate-x-5' : 'translate-x-0.5'}`} />
        </button>
      </div>
    );
  };

  const Section = ({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) => (
    <div className="rounded-lg border border-border bg-card p-5">
      <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
        <Icon size={15} className="text-primary" />
        {title}
      </h3>
      {children}
    </div>
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Cài đặt" description="Cấu hình cá nhân cho HQG Security Platform" />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Thông báo" icon={Bell}>
          <Toggle label="Thiết bị mới" description="Cảnh báo khi phát hiện thiết bị lạ" defaultOn />
          <Toggle label="Kết nối ra ngoài" description="Cảnh báo khi IoT kết nối Internet" defaultOn />
          <Toggle label="Email thông báo" description="Gửi email cho Critical alerts" />
          <Toggle label="Thông báo trên dashboard" description="Hiển thị popup cảnh báo" defaultOn />
        </Section>

        <Section title="Giao diện" icon={Settings}>
          <Toggle label="Hiệu ứng chuyển trang" description="Animation khi chuyển giữa các trang" defaultOn />
          <Toggle label="Auto-refresh dashboard" description="Tự động cập nhật dashboard mỗi 30s" defaultOn />
          <Toggle label="Compact mode" description="Hiển thị bảng với khoảng cách nhỏ hơn" />
        </Section>

        <Section title="Bảo mật cá nhân" icon={Shield}>
          <Toggle label="Xác thực 2 yếu tố" description="Bật 2FA cho tài khoản của bạn" />
          <Toggle label="Khóa tự động" description="Khóa phiên sau 15 phút không hoạt động" defaultOn />
        </Section>

        <Section title="Dữ liệu" icon={Database}>
          <Toggle label="Lưu bộ lọc" description="Nhớ bộ lọc đã chọn khi quay lại trang" defaultOn />
          <Toggle label="Xuất báo cáo" description="Cho phép xuất dữ liệu ra CSV/PDF" defaultOn />
        </Section>
      </div>

      <div className="rounded-lg border border-border bg-card p-5">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Info size={14} />
          <span>HQG Security Platform v2.1.0 • Build 2026.04.08 • © 2026 HQG Security Team</span>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
