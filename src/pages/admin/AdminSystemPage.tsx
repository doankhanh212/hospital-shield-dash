import { Cog, Save } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { useState } from 'react';

const AdminSystemPage = () => {
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const InputField = ({ label, defaultValue, type = 'text', hint }: { label: string; defaultValue: string; type?: string; hint?: string }) => (
    <div>
      <label className="block text-xs font-medium text-foreground mb-1.5">{label}</label>
      <input
        type={type}
        defaultValue={defaultValue}
        className="w-full rounded-lg border border-border bg-background px-3 py-2.5 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
      />
      {hint && <p className="mt-1 text-[10px] text-muted-foreground">{hint}</p>}
    </div>
  );

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

  const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div className="rounded-lg border border-border bg-card p-5">
      <h3 className="mb-4 text-sm font-semibold text-foreground">{title}</h3>
      {children}
    </div>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cấu hình hệ thống"
        description="Thiết lập chung cho HQG Security Platform"
        actions={
          <button
            onClick={handleSave}
            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
          >
            <Save size={14} />
            {saved ? 'Đã lưu ✓' : 'Lưu thay đổi'}
          </button>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Thông tin hệ thống">
          <div className="space-y-4">
            <InputField label="Tên hệ thống" defaultValue="HQG Security Platform" />
            <InputField label="Phiên bản" defaultValue="2.1.0" hint="Phiên bản hiện tại của nền tảng" />
            <InputField label="Tên bệnh viện" defaultValue="Bệnh viện Đa khoa HQG" />
            <InputField label="Email quản trị" defaultValue="soc@hospital.local" />
          </div>
        </Section>

        <Section title="Quét mạng">
          <div className="space-y-4">
            <InputField label="Dải mạng quét" defaultValue="10.0.0.0/16" hint="CIDR notation" />
            <InputField label="Tần suất quét (phút)" defaultValue="30" type="number" />
            <Toggle label="Quét tự động" description="Tự động quét mạng theo lịch" defaultOn />
            <Toggle label="Quét sâu (Deep scan)" description="Phân tích fingerprint, JA3, DHCP" defaultOn />
          </div>
        </Section>

        <Section title="Bảo mật">
          <Toggle label="Xác thực 2 yếu tố (2FA)" description="Bắt buộc 2FA cho tất cả tài khoản" />
          <Toggle label="Khóa phiên tự động" description="Tự động đăng xuất sau 15 phút không hoạt động" defaultOn />
          <Toggle label="Ghi nhật ký đăng nhập" description="Lưu lại tất cả hoạt động đăng nhập" defaultOn />
        </Section>

        <Section title="Dữ liệu & Lưu trữ">
          <div className="space-y-4">
            <InputField label="Thời gian lưu nhật ký (ngày)" defaultValue="90" type="number" />
            <Toggle label="Sao lưu tự động" description="Sao lưu cấu hình và dữ liệu hàng ngày" defaultOn />
            <Toggle label="Nén dữ liệu cũ" description="Tự động nén nhật ký sau 30 ngày" defaultOn />
          </div>
        </Section>
      </div>
    </div>
  );
};

export default AdminSystemPage;
