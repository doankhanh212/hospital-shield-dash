import { Settings, Shield, Bell, Network, Database } from 'lucide-react';

const SettingsPage = () => {
  const Section = ({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) => (
    <div className="rounded-lg border border-border bg-card p-5">
      <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
        <Icon size={16} className="text-primary" />
        {title}
      </h3>
      {children}
    </div>
  );

  const Toggle = ({ label, description, defaultOn = false }: { label: string; description: string; defaultOn?: boolean }) => (
    <div className="flex items-center justify-between border-b border-border/50 py-3 last:border-0">
      <div>
        <p className="text-sm text-foreground">{label}</p>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <div className={`relative h-6 w-11 cursor-pointer rounded-full transition-colors ${defaultOn ? 'bg-primary' : 'bg-muted'}`}>
        <div className={`absolute top-0.5 h-5 w-5 rounded-full bg-foreground shadow transition-transform ${defaultOn ? 'translate-x-5' : 'translate-x-0.5'}`} />
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-foreground">Cài đặt</h2>
        <p className="text-sm text-muted-foreground">Cấu hình hệ thống HQG Security Platform</p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Quét mạng" icon={Network}>
          <Toggle label="Quét tự động" description="Quét mạng mỗi 30 phút" defaultOn />
          <Toggle label="Quét sâu" description="Phân tích fingerprint và hành vi" defaultOn />
          <Toggle label="Quét lỗ hổng" description="Kiểm tra CVE cho thiết bị đã biết" defaultOn />
        </Section>

        <Section title="Cảnh báo" icon={Bell}>
          <Toggle label="Thiết bị mới" description="Cảnh báo khi phát hiện thiết bị lạ" defaultOn />
          <Toggle label="Kết nối ra ngoài" description="Cảnh báo khi IoT kết nối Internet" defaultOn />
          <Toggle label="Email thông báo" description="Gửi email cho Critical alerts" />
        </Section>

        <Section title="Bảo mật" icon={Shield}>
          <Toggle label="Xác thực 2 yếu tố" description="Yêu cầu 2FA cho tất cả tài khoản" />
          <Toggle label="Khóa tự động" description="Khóa phiên sau 15 phút không hoạt động" defaultOn />
        </Section>

        <Section title="Dữ liệu" icon={Database}>
          <Toggle label="Lưu nhật ký" description="Lưu trữ nhật ký trong 90 ngày" defaultOn />
          <Toggle label="Sao lưu tự động" description="Sao lưu cấu hình hàng ngày" defaultOn />
        </Section>
      </div>
    </div>
  );
};

export default SettingsPage;
