import { Save, Play, Square, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { useState } from 'react';
import { useScanStatus, useScanStart, useScanStop } from '@/hooks/useApi';

const AdminSystemPage = () => {
  const [saved, setSaved] = useState(false);

  // Scan control
  const { data: scanStatus } = useScanStatus();
  const scanStart = useScanStart();
  const scanStop = useScanStop();
  const [scanMode, setScanMode] = useState<'file' | 'live'>('file');
  const [logDir, setLogDir] = useState('/logs');

  // System info
  const [sysName, setSysName] = useState('HQG Security Platform');
  const [sysVersion] = useState('2.1.0');
  const [hospitalName, setHospitalName] = useState('Bệnh viện Đa khoa HQG');
  const [adminEmail, setAdminEmail] = useState('soc@hospital.local');

  // Network scan
  const [scanRange, setScanRange] = useState('10.0.0.0/16');
  const [scanInterval, setScanInterval] = useState('30');
  const [excludeRanges, setExcludeRanges] = useState('169.254.0.0/16, 224.0.0.0/4');

  // Data retention
  const [retentionDays, setRetentionDays] = useState('90');

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const InputField = ({
    label,
    value,
    onChange,
    type = 'text',
    hint,
    readOnly,
  }: {
    label: string;
    value: string;
    onChange: (v: string) => void;
    type?: string;
    hint?: string;
    readOnly?: boolean;
  }) => (
    <div>
      <label className="block text-xs font-medium text-foreground mb-1.5">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        readOnly={readOnly}
        className={`w-full rounded-lg border border-border px-3 py-2.5 text-sm text-foreground transition-colors ${
          readOnly
            ? 'bg-muted/50 cursor-default text-muted-foreground'
            : 'bg-background focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30'
        }`}
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
          <div className="flex items-center gap-3">
            {saved && (
              <span className="rounded-lg border border-success/30 bg-success/10 px-3 py-1.5 text-xs font-medium text-success">
                Cấu hình đã được lưu ✓
              </span>
            )}
            <button
              onClick={handleSave}
              className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
            >
              <Save size={14} />
              Lưu thay đổi
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Thông tin hệ thống">
          <div className="space-y-4">
            <InputField label="Tên hệ thống" value={sysName} onChange={setSysName} />
            <InputField label="Phiên bản" value={sysVersion} onChange={() => {}} readOnly hint="Phiên bản hiện tại của nền tảng" />
            <InputField label="Tên bệnh viện" value={hospitalName} onChange={setHospitalName} />
            <InputField label="Email quản trị" value={adminEmail} onChange={setAdminEmail} />
          </div>
        </Section>

        <Section title="Quét mạng">
          <div className="space-y-4">
            <InputField label="Dải mạng quét" value={scanRange} onChange={setScanRange} hint="CIDR notation" />
            <InputField label="Tần suất quét (phút)" value={scanInterval} onChange={setScanInterval} type="number" />
            <InputField
              label="Dải mạng loại trừ"
              value={excludeRanges}
              onChange={setExcludeRanges}
              hint="Không tạo asset cho các dải IP này"
            />
            <Toggle label="Quét tự động" description="Tự động quét mạng theo lịch" defaultOn />
            <Toggle label="Quét sâu (Deep scan)" description="Phân tích fingerprint, JA3, DHCP" defaultOn />
          </div>
        </Section>

        <Section title="Nhận dạng thiết bị">
          <Toggle
            label="Phân tích JA3/JA3s"
            description="Nhận dạng qua TLS fingerprint"
            defaultOn
          />
          <Toggle
            label="DHCP Fingerprinting"
            description="Nhận dạng qua DHCP vendor class"
            defaultOn
          />
          <Toggle
            label="User-Agent parsing"
            description="Nhận dạng qua HTTP User-Agent"
            defaultOn
          />
          <Toggle
            label="CPE matching"
            description="Đối chiếu CPE với NVD database (cần internet)"
            defaultOn={false}
          />
        </Section>

        <Section title="Bảo mật">
          <Toggle label="Xác thực 2 yếu tố (2FA)" description="Bắt buộc 2FA cho tất cả tài khoản" />
          <Toggle label="Khóa phiên tự động" description="Tự động đăng xuất sau 15 phút không hoạt động" defaultOn />
          <Toggle label="Ghi nhật ký đăng nhập" description="Lưu lại tất cả hoạt động đăng nhập" defaultOn />
        </Section>

        <Section title="Dữ liệu & Lưu trữ">
          <div className="space-y-4">
            <InputField label="Thời gian lưu nhật ký (ngày)" value={retentionDays} onChange={setRetentionDays} type="number" />
            <Toggle label="Sao lưu tự động" description="Sao lưu cấu hình và dữ liệu hàng ngày" defaultOn />
            <Toggle label="Nén dữ liệu cũ" description="Tự động nén nhật ký sau 30 ngày" defaultOn />
          </div>
        </Section>

        {/* --- Scan Control --- */}
        <Section title="Kiểm soát quét (Zeek)">
          <div className="space-y-4">
            {/* Status banner */}
            {scanStatus && (
              <div className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs border ${
                scanStatus.running
                  ? 'border-success/30 bg-success/10 text-success'
                  : scanStatus.status === 'failed'
                  ? 'border-destructive/30 bg-destructive/10 text-destructive'
                  : 'border-border bg-muted/50 text-muted-foreground'
              }`}>
                {scanStatus.running
                  ? <><Loader2 size={13} className="animate-spin shrink-0" /> Đang quét — {scanStatus.mode} mode</>
                  : scanStatus.status === 'failed'
                  ? <><AlertCircle size={13} className="shrink-0" /> Lỗi: {scanStatus.error ?? 'không rõ'}</>
                  : <><CheckCircle2 size={13} className="shrink-0" /> Trạng thái: {scanStatus.status || 'idle'}</>
                }
              </div>
            )}

            {/* Metrics */}
            {scanStatus?.running && (
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'Logs', value: scanStatus.logs_processed?.toLocaleString() ?? '—' },
                  { label: 'Tài sản', value: scanStatus.assets_discovered?.toLocaleString() ?? '—' },
                  { label: 'Tốc độ', value: scanStatus.ingestion_rate ? `${scanStatus.ingestion_rate}/s` : '—' },
                ].map(m => (
                  <div key={m.label} className="rounded-lg border border-border bg-muted/30 px-3 py-2 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{m.label}</p>
                    <p className="text-sm font-semibold text-foreground font-mono">{m.value}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Mode selector */}
            <div>
              <label className="mb-1.5 block text-xs font-medium text-foreground">Chế độ quét</label>
              <div className="flex gap-2">
                {(['file', 'live'] as const).map(m => (
                  <button
                    key={m}
                    onClick={() => setScanMode(m)}
                    className={`flex-1 rounded-lg border py-2 text-xs font-medium transition-colors ${
                      scanMode === m ? 'border-primary bg-primary/10 text-primary' : 'border-border bg-card text-muted-foreground hover:bg-accent'
                    }`}
                  >
                    {m === 'file' ? 'File mode' : 'Live capture'}
                  </button>
                ))}
              </div>
            </div>

            {scanMode === 'file' && (
              <div>
                <label className="mb-1.5 block text-xs font-medium text-foreground">Thư mục log</label>
                <input
                  value={logDir}
                  onChange={e => setLogDir(e.target.value)}
                  className="w-full rounded-lg border border-border bg-background px-3 py-2.5 text-sm font-mono text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
                  placeholder="/logs"
                />
              </div>
            )}

            {/* Action buttons */}
            {(scanStart.error || scanStop.error) && (
              <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                <AlertCircle size={13} />
                {scanStart.error instanceof Error ? scanStart.error.message : scanStop.error instanceof Error ? scanStop.error.message : 'Lỗi'}
              </div>
            )}

            <div className="flex gap-2">
              <button
                disabled={scanStatus?.running || scanStart.isPending}
                onClick={() => scanStart.mutate({ mode: scanMode, log_dir: scanMode === 'file' ? logDir : undefined })}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-success px-4 py-2 text-xs font-medium text-white hover:bg-success/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {scanStart.isPending ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
                Bắt đầu quét
              </button>
              <button
                disabled={!scanStatus?.running || scanStop.isPending}
                onClick={() => scanStop.mutate()}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-destructive px-4 py-2 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {scanStop.isPending ? <Loader2 size={13} className="animate-spin" /> : <Square size={13} />}
                Dừng quét
              </button>
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
};

export default AdminSystemPage;
