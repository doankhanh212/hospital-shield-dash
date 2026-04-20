import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Wand2,
  Trash2,
  Plus,
  ChevronLeft,
  ChevronRight,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Server,
  Monitor,
  Activity,
  Camera,
  Network as NetworkIcon,
  HelpCircle,
  Rocket,
  ArrowRight,
} from 'lucide-react';

import PageHeader from '@/components/widgets/PageHeader';
import {
  runGenerator,
  type DeviceType,
  type GenerateResult,
  type NetworkConfig,
  type VlanConfig,
} from '@/lib/api';

// ── Constants ────────────────────────────────────────────────────────

const DEVICE_TYPES: DeviceType[] = [
  'IoMT',
  'IoT',
  'Workstation',
  'Server',
  'Network',
  'Unknown',
];

const DEVICE_TYPE_COLORS: Record<DeviceType, string> = {
  IoMT: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
  IoT: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  Workstation: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  Server: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
  Network: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
  Unknown: 'bg-red-500/10 text-red-500 border-red-500/20',
};

const DEVICE_TYPE_ICONS: Record<DeviceType, React.ElementType> = {
  IoMT: Activity,
  IoT: Camera,
  Workstation: Monitor,
  Server: Server,
  Network: NetworkIcon,
  Unknown: HelpCircle,
};

const DEFAULT_VLANS: VlanConfig[] = [
  { vlan_id: 10, name: 'IoMT', subnet: '10.10.10.0/24', device_type: 'IoMT', device_count: 10 },
  { vlan_id: 20, name: 'Workstation', subnet: '10.10.20.0/24', device_type: 'Workstation', device_count: 20 },
  { vlan_id: 30, name: 'Server', subnet: '10.10.30.0/24', device_type: 'Server', device_count: 5 },
  { vlan_id: 40, name: 'IoT/Camera', subnet: '10.10.40.0/24', device_type: 'IoT', device_count: 10 },
  { vlan_id: 50, name: 'Network', subnet: '10.10.50.0/24', device_type: 'Network', device_count: 5 },
];

const STEPS = [
  { id: 1, title: 'Tổ chức', description: 'Thông tin tổ chức' },
  { id: 2, title: 'VLAN', description: 'Cấu hình VLAN' },
  { id: 3, title: 'Mô phỏng', description: 'Tùy chọn mô phỏng' },
  { id: 4, title: 'Xác nhận', description: 'Xác nhận & Generate' },
];

// ── Validation helpers ───────────────────────────────────────────────

const CIDR_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}\/([0-9]|[12][0-9]|3[0-2])$/;
const IP_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const isValidCidr = (s: string) => {
  if (!CIDR_REGEX.test(s)) return false;
  const [ip] = s.split('/');
  return ip.split('.').every(o => Number(o) >= 0 && Number(o) <= 255);
};

const isValidIp = (s: string) => {
  if (!IP_REGEX.test(s)) return false;
  return s.split('.').every(o => Number(o) >= 0 && Number(o) <= 255);
};

// ── Page ─────────────────────────────────────────────────────────────

const AdminSetupWizardPage = () => {
  const navigate = useNavigate();

  // Wizard state
  const [step, setStep] = useState<number>(1);

  // Step 1 — org
  const [orgName, setOrgName] = useState('Bệnh viện Đa khoa');
  const [domain, setDomain] = useState('hospital.local');
  const [dnsServer, setDnsServer] = useState('10.0.0.1');

  // Step 2 — vlans
  const [vlans, setVlans] = useState<VlanConfig[]>(DEFAULT_VLANS);

  // Step 3 — simulation
  const [simulateDays, setSimulateDays] = useState<number>(1);
  const [eventsPerDevice, setEventsPerDevice] = useState<number>(100);

  // Step 4 — generate state
  const [generating, setGenerating] = useState(false);
  const [progressPhase, setProgressPhase] = useState<0 | 1 | 2 | 3>(0);
  const [result, setResult] = useState<GenerateResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ── Derived ────────────────────────────────────────────────────────

  const totalDevices = useMemo(
    () => vlans.reduce((sum, v) => sum + (Number(v.device_count) || 0), 0),
    [vlans],
  );

  const estimatedEvents = totalDevices * eventsPerDevice;
  const estimatedIngestSec = Math.max(1, Math.ceil(estimatedEvents * 0.05));

  // ── Validation per step ────────────────────────────────────────────

  const step1Errors = useMemo(() => {
    const errs: Record<string, string> = {};
    if (!orgName.trim()) errs.orgName = 'Tên tổ chức là bắt buộc';
    if (!DOMAIN_REGEX.test(domain)) errs.domain = 'Domain không hợp lệ (VD: hospital.local)';
    if (!isValidIp(dnsServer)) errs.dnsServer = 'DNS server phải là địa chỉ IP hợp lệ';
    return errs;
  }, [orgName, domain, dnsServer]);

  const step2Errors = useMemo(() => {
    const errs: Record<string, string> = {};
    if (vlans.length === 0) errs._global = 'Cần ít nhất 1 VLAN';
    const seenIds = new Set<number>();
    vlans.forEach((v, i) => {
      if (seenIds.has(v.vlan_id)) errs[`vlan_id_${i}`] = 'VLAN ID trùng lặp';
      seenIds.add(v.vlan_id);
      if (v.vlan_id < 1 || v.vlan_id > 4094) errs[`vlan_id_${i}`] = 'VLAN ID phải từ 1-4094';
      if (!v.name.trim()) errs[`name_${i}`] = 'Tên VLAN không được trống';
      if (!isValidCidr(v.subnet)) errs[`subnet_${i}`] = 'Subnet CIDR không hợp lệ';
      if (v.device_count < 1 || v.device_count > 200)
        errs[`device_count_${i}`] = 'Số lượng phải từ 1-200';
    });
    return errs;
  }, [vlans]);

  const currentStepValid = useMemo(() => {
    if (step === 1) return Object.keys(step1Errors).length === 0;
    if (step === 2) return Object.keys(step2Errors).length === 0;
    return true;
  }, [step, step1Errors, step2Errors]);

  // ── VLAN helpers ───────────────────────────────────────────────────

  const updateVlan = (idx: number, patch: Partial<VlanConfig>) => {
    setVlans(v => v.map((row, i) => (i === idx ? { ...row, ...patch } : row)));
  };

  const addVlan = () => {
    const nextId =
      vlans.length === 0 ? 10 : Math.max(...vlans.map(v => v.vlan_id)) + 10;
    setVlans(v => [
      ...v,
      {
        vlan_id: nextId,
        name: `VLAN ${nextId}`,
        subnet: `10.10.${nextId}.0/24`,
        device_type: 'Workstation',
        device_count: 5,
      },
    ]);
  };

  const removeVlan = (idx: number) => {
    if (vlans.length <= 1) return;
    setVlans(v => v.filter((_, i) => i !== idx));
  };

  // ── Generate ───────────────────────────────────────────────────────

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    setResult(null);
    setProgressPhase(1);

    const config: NetworkConfig = {
      org_name: orgName,
      domain,
      dns_server: dnsServer,
      vlans,
      simulate_days: simulateDays,
      events_per_device: eventsPerDevice,
    };

    // Progress phase timers — purely visual
    const t2 = setTimeout(() => setProgressPhase(2), 2000);
    const t3 = setTimeout(() => setProgressPhase(3), 5000);

    try {
      const r = await runGenerator(config);
      setResult(r);
    } catch (e: any) {
      const msg = e?.message || String(e) || 'Không rõ nguyên nhân';
      setError(msg);
    } finally {
      clearTimeout(t2);
      clearTimeout(t3);
      setGenerating(false);
    }
  };

  const handleRetry = () => {
    setError(null);
    setResult(null);
    setProgressPhase(0);
  };

  // ── Render helpers ─────────────────────────────────────────────────

  const StepIndicator = () => (
    <div className="flex items-center gap-2">
      {STEPS.map((s, i) => {
        const active = step === s.id;
        const done = step > s.id;
        return (
          <div key={s.id} className="flex items-center">
            <div
              className={`flex h-8 items-center gap-2 rounded-full border px-3 text-[11px] font-medium transition-all ${
                active
                  ? 'border-primary bg-primary/10 text-primary'
                  : done
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-500'
                  : 'border-border bg-card text-muted-foreground'
              }`}
            >
              <span
                className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${
                  active
                    ? 'bg-primary text-primary-foreground'
                    : done
                    ? 'bg-emerald-500 text-white'
                    : 'bg-muted text-muted-foreground'
                }`}
              >
                {done ? <CheckCircle2 size={12} /> : s.id}
              </span>
              <span className="hidden sm:inline">{s.title}</span>
            </div>
            {i < STEPS.length - 1 && (
              <div className={`mx-1 h-px w-4 ${done ? 'bg-emerald-500/40' : 'bg-border'}`} />
            )}
          </div>
        );
      })}
    </div>
  );

  const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div className="rounded-lg border border-border bg-card p-5">
      <h3 className="mb-4 text-sm font-semibold text-foreground">{title}</h3>
      {children}
    </div>
  );

  const InputField = ({
    label,
    value,
    onChange,
    type = 'text',
    hint,
    error,
  }: {
    label: string;
    value: string;
    onChange: (v: string) => void;
    type?: string;
    hint?: string;
    error?: string;
  }) => (
    <div>
      <label className="block text-xs font-medium text-foreground mb-1.5">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        className={`w-full rounded-lg border bg-background px-3 py-2.5 text-sm text-foreground focus:outline-none focus:ring-1 transition-colors ${
          error
            ? 'border-critical focus:border-critical focus:ring-critical/30'
            : 'border-border focus:border-primary focus:ring-primary/30'
        }`}
      />
      {error ? (
        <p className="mt-1 text-[10px] text-critical">{error}</p>
      ) : hint ? (
        <p className="mt-1 text-[10px] text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );

  // ── Step renders ───────────────────────────────────────────────────

  const renderStep1 = () => (
    <Section title="Thông tin tổ chức">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="md:col-span-2">
          <InputField
            label="Tên tổ chức"
            value={orgName}
            onChange={setOrgName}
            error={step1Errors.orgName}
          />
        </div>
        <InputField
          label="Tên miền nội bộ"
          value={domain}
          onChange={setDomain}
          hint="Dùng cho hostname thiết bị, VD: device-01.hospital.local"
          error={step1Errors.domain}
        />
        <InputField
          label="DNS Server"
          value={dnsServer}
          onChange={setDnsServer}
          error={step1Errors.dnsServer}
        />
      </div>
    </Section>
  );

  const renderStep2 = () => (
    <Section title="Cấu hình VLAN">
      <div className="space-y-3">
        {vlans.map((v, i) => {
          const Icon = DEVICE_TYPE_ICONS[v.device_type];
          return (
            <div
              key={i}
              className="rounded-lg border border-border bg-background/50 p-4"
            >
              <div className="flex items-start gap-3">
                <div
                  className={`mt-6 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${DEVICE_TYPE_COLORS[v.device_type]}`}
                >
                  <Icon size={16} />
                </div>
                <div className="grid flex-1 grid-cols-2 gap-3 md:grid-cols-6">
                  <div>
                    <label className="block text-[10px] font-medium text-muted-foreground mb-1">VLAN ID</label>
                    <input
                      type="number"
                      min={1}
                      max={4094}
                      value={v.vlan_id}
                      onChange={e => updateVlan(i, { vlan_id: Number(e.target.value) })}
                      className={`w-full rounded-md border bg-background px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 ${
                        step2Errors[`vlan_id_${i}`]
                          ? 'border-critical focus:ring-critical/30'
                          : 'border-border focus:border-primary focus:ring-primary/30'
                      }`}
                    />
                    {step2Errors[`vlan_id_${i}`] && (
                      <p className="mt-1 text-[10px] text-critical">{step2Errors[`vlan_id_${i}`]}</p>
                    )}
                  </div>
                  <div className="col-span-1">
                    <label className="block text-[10px] font-medium text-muted-foreground mb-1">Tên VLAN</label>
                    <input
                      type="text"
                      value={v.name}
                      onChange={e => updateVlan(i, { name: e.target.value })}
                      className={`w-full rounded-md border bg-background px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 ${
                        step2Errors[`name_${i}`]
                          ? 'border-critical focus:ring-critical/30'
                          : 'border-border focus:border-primary focus:ring-primary/30'
                      }`}
                    />
                    {step2Errors[`name_${i}`] && (
                      <p className="mt-1 text-[10px] text-critical">{step2Errors[`name_${i}`]}</p>
                    )}
                  </div>
                  <div className="col-span-2">
                    <label className="block text-[10px] font-medium text-muted-foreground mb-1">Subnet (CIDR)</label>
                    <input
                      type="text"
                      value={v.subnet}
                      onChange={e => updateVlan(i, { subnet: e.target.value })}
                      placeholder="10.10.10.0/24"
                      className={`w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs text-foreground focus:outline-none focus:ring-1 ${
                        step2Errors[`subnet_${i}`]
                          ? 'border-critical focus:ring-critical/30'
                          : 'border-border focus:border-primary focus:ring-primary/30'
                      }`}
                    />
                    {step2Errors[`subnet_${i}`] && (
                      <p className="mt-1 text-[10px] text-critical">{step2Errors[`subnet_${i}`]}</p>
                    )}
                  </div>
                  <div>
                    <label className="block text-[10px] font-medium text-muted-foreground mb-1">Loại thiết bị</label>
                    <select
                      value={v.device_type}
                      onChange={e => updateVlan(i, { device_type: e.target.value as DeviceType })}
                      className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30"
                    >
                      {DEVICE_TYPES.map(t => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-medium text-muted-foreground mb-1">Số lượng</label>
                    <input
                      type="number"
                      min={1}
                      max={200}
                      value={v.device_count}
                      onChange={e => updateVlan(i, { device_count: Number(e.target.value) })}
                      className={`w-full rounded-md border bg-background px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 ${
                        step2Errors[`device_count_${i}`]
                          ? 'border-critical focus:ring-critical/30'
                          : 'border-border focus:border-primary focus:ring-primary/30'
                      }`}
                    />
                    {step2Errors[`device_count_${i}`] && (
                      <p className="mt-1 text-[10px] text-critical">{step2Errors[`device_count_${i}`]}</p>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => removeVlan(i)}
                  disabled={vlans.length <= 1}
                  className="mt-6 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border text-muted-foreground transition-colors hover:border-critical/40 hover:bg-critical/10 hover:text-critical disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-border disabled:hover:bg-transparent disabled:hover:text-muted-foreground"
                  title="Xóa VLAN"
                >
                  <Trash2 size={14} />
                </button>
              </div>
              <div className="mt-3 flex items-center gap-2 pl-12">
                <span
                  className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${DEVICE_TYPE_COLORS[v.device_type]}`}
                >
                  {v.device_type}
                </span>
                <span className="text-[10px] text-muted-foreground">
                  {v.device_count} thiết bị • {v.subnet}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <button
        onClick={addVlan}
        className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-background/30 px-3 py-2.5 text-xs font-medium text-muted-foreground transition-colors hover:border-primary/50 hover:bg-primary/5 hover:text-primary"
      >
        <Plus size={14} />
        Thêm VLAN
      </button>

      <div className="mt-4 flex items-center justify-between rounded-lg border border-border bg-background/50 px-4 py-3">
        <div className="text-xs text-muted-foreground">
          Tổng:{' '}
          <span className="font-semibold text-foreground">{totalDevices}</span>{' '}
          thiết bị •{' '}
          <span className="font-semibold text-foreground">{vlans.length}</span> VLANs
        </div>
        {step2Errors._global && (
          <span className="text-[10px] text-critical">{step2Errors._global}</span>
        )}
      </div>
    </Section>
  );

  const renderStep3 = () => (
    <div className="space-y-5">
      <Section title="Tùy chọn mô phỏng">
        <div className="space-y-6">
          {/* simulate_days */}
          <div>
            <label className="block text-xs font-medium text-foreground mb-2">
              Thời gian mô phỏng
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[1, 3, 7].map(d => (
                <button
                  key={d}
                  onClick={() => setSimulateDays(d)}
                  className={`flex items-center justify-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium transition-all ${
                    simulateDays === d
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border bg-background text-foreground hover:border-primary/40'
                  }`}
                >
                  <span
                    className={`flex h-4 w-4 items-center justify-center rounded-full border-2 ${
                      simulateDays === d ? 'border-primary' : 'border-border'
                    }`}
                  >
                    {simulateDays === d && <span className="h-2 w-2 rounded-full bg-primary" />}
                  </span>
                  {d} ngày
                </button>
              ))}
            </div>
          </div>

          {/* events_per_device */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <label className="text-xs font-medium text-foreground">
                Mật độ sự kiện
              </label>
              <span className="text-xs font-semibold text-primary">
                {eventsPerDevice} sự kiện/thiết bị
              </span>
            </div>
            <input
              type="range"
              min={10}
              max={500}
              step={10}
              value={eventsPerDevice}
              onChange={e => setEventsPerDevice(Number(e.target.value))}
              className="w-full accent-primary"
            />
            <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
              <span>Thấp (10)</span>
              <span>Trung bình (250)</span>
              <span>Cao (500)</span>
            </div>
          </div>
        </div>
      </Section>

      <Section title="Ước tính">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-border bg-background/50 p-4">
            <p className="text-[11px] text-muted-foreground">Tổng thiết bị</p>
            <p className="mt-1 text-2xl font-bold text-foreground">{totalDevices}</p>
          </div>
          <div className="rounded-lg border border-border bg-background/50 p-4">
            <p className="text-[11px] text-muted-foreground">Ước tính sự kiện</p>
            <p className="mt-1 text-2xl font-bold text-foreground">
              {estimatedEvents.toLocaleString()}
            </p>
          </div>
          <div className="rounded-lg border border-border bg-background/50 p-4">
            <p className="text-[11px] text-muted-foreground">Ước tính thời gian ingest</p>
            <p className="mt-1 text-2xl font-bold text-foreground">~{estimatedIngestSec}s</p>
          </div>
        </div>
      </Section>
    </div>
  );

  const renderStep4 = () => {
    if (result) {
      return (
        <Section title="Kết quả">
          <div className="space-y-4">
            <div className="flex items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-500">
                <CheckCircle2 size={20} />
              </div>
              <div className="flex-1">
                <p className="text-sm font-semibold text-foreground">
                  {result.status === 'partial' ? 'Hoàn tất một phần' : 'Tạo dữ liệu thành công'}
                </p>
                <p className="text-xs text-muted-foreground">{result.message}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded-lg border border-border bg-background/50 p-4">
                <p className="text-[11px] text-muted-foreground">Tổng thiết bị đã tạo</p>
                <p className="mt-1 text-2xl font-bold text-foreground">
                  {result.total_devices}
                </p>
              </div>
              <div className="rounded-lg border border-border bg-background/50 p-4">
                <p className="text-[11px] text-muted-foreground">Tổng sự kiện</p>
                <p className="mt-1 text-2xl font-bold text-foreground">
                  {result.total_events.toLocaleString()}
                </p>
              </div>
              <div className="rounded-lg border border-border bg-background/50 p-4">
                <p className="text-[11px] text-muted-foreground">Số file Zeek</p>
                <p className="mt-1 text-2xl font-bold text-foreground">
                  {result.files_written.length}
                </p>
              </div>
            </div>

            <div>
              <p className="mb-2 text-xs font-medium text-foreground">Phân loại theo loại thiết bị</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.device_counts).map(([type, count]) => {
                  const dt = type as DeviceType;
                  const colorClass = DEVICE_TYPE_COLORS[dt] ?? DEVICE_TYPE_COLORS.Unknown;
                  return (
                    <span
                      key={type}
                      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${colorClass}`}
                    >
                      {type}: <span className="font-bold">{count}</span>
                    </span>
                  );
                })}
              </div>
            </div>

            <div className="rounded-lg border border-border bg-background/50 p-3">
              <p className="text-[10px] text-muted-foreground">Thư mục log</p>
              <p className="mt-0.5 break-all font-mono text-[11px] text-foreground">
                {result.log_dir}
              </p>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => {
                  setResult(null);
                  setStep(1);
                }}
                className="rounded-lg border border-border bg-background px-4 py-2 text-xs font-medium text-foreground transition-colors hover:bg-muted"
              >
                Tạo dữ liệu mới
              </button>
              <button
                onClick={() => navigate('/assets')}
                className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                Xem tài sản
                <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </Section>
      );
    }

    if (error) {
      return (
        <Section title="Lỗi">
          <div className="space-y-4">
            <div className="flex items-start gap-3 rounded-lg border border-critical/30 bg-critical/5 p-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-critical/15 text-critical">
                <AlertCircle size={20} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-foreground">Không thể tạo dữ liệu</p>
                <p className="mt-1 break-words text-xs text-muted-foreground">{error}</p>
              </div>
            </div>
            <div className="flex justify-end">
              <button
                onClick={handleRetry}
                className="rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
              >
                Thử lại
              </button>
            </div>
          </div>
        </Section>
      );
    }

    if (generating) {
      const phases = [
        { id: 1, label: 'Đang tạo Zeek logs...' },
        { id: 2, label: 'Đang ingest vào database...' },
        { id: 3, label: 'Đang phân loại thiết bị...' },
      ];
      return (
        <Section title="Đang xử lý">
          <div className="space-y-3">
            {phases.map(p => {
              const active = progressPhase === p.id;
              const done = progressPhase > p.id;
              return (
                <div
                  key={p.id}
                  className={`flex items-center gap-3 rounded-lg border px-4 py-3 transition-all ${
                    active
                      ? 'border-primary/40 bg-primary/5'
                      : done
                      ? 'border-emerald-500/30 bg-emerald-500/5'
                      : 'border-border bg-background/40'
                  }`}
                >
                  <div className="flex h-8 w-8 items-center justify-center">
                    {done ? (
                      <CheckCircle2 size={18} className="text-emerald-500" />
                    ) : active ? (
                      <Loader2 size={18} className="animate-spin text-primary" />
                    ) : (
                      <div className="h-2 w-2 rounded-full bg-muted" />
                    )}
                  </div>
                  <span
                    className={`text-sm ${
                      active
                        ? 'font-medium text-foreground'
                        : done
                        ? 'text-emerald-500'
                        : 'text-muted-foreground'
                    }`}
                  >
                    {p.label}
                  </span>
                </div>
              );
            })}
          </div>
        </Section>
      );
    }

    // Pre-run confirmation view
    return (
      <div className="space-y-5">
        <Section title="Tổ chức">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <div>
              <p className="text-[10px] text-muted-foreground">Tên tổ chức</p>
              <p className="mt-0.5 text-sm font-medium text-foreground">{orgName}</p>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground">Tên miền</p>
              <p className="mt-0.5 font-mono text-sm text-foreground">{domain}</p>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground">DNS Server</p>
              <p className="mt-0.5 font-mono text-sm text-foreground">{dnsServer}</p>
            </div>
          </div>
        </Section>

        <Section title={`VLAN (${vlans.length})`}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <th className="pb-2 font-medium">VLAN ID</th>
                  <th className="pb-2 font-medium">Tên</th>
                  <th className="pb-2 font-medium">Subnet</th>
                  <th className="pb-2 font-medium">Loại</th>
                  <th className="pb-2 text-right font-medium">Số lượng</th>
                </tr>
              </thead>
              <tbody>
                {vlans.map((v, i) => (
                  <tr key={i} className="border-b border-border/30 last:border-0">
                    <td className="py-2 font-mono text-foreground">{v.vlan_id}</td>
                    <td className="py-2 text-foreground">{v.name}</td>
                    <td className="py-2 font-mono text-muted-foreground">{v.subnet}</td>
                    <td className="py-2">
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${DEVICE_TYPE_COLORS[v.device_type]}`}
                      >
                        {v.device_type}
                      </span>
                    </td>
                    <td className="py-2 text-right font-semibold text-foreground">{v.device_count}</td>
                  </tr>
                ))}
                <tr className="bg-background/50">
                  <td colSpan={4} className="py-2 text-[11px] font-medium text-muted-foreground">
                    Tổng cộng
                  </td>
                  <td className="py-2 text-right text-sm font-bold text-primary">{totalDevices}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </Section>

        <Section title="Tùy chọn mô phỏng">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <div>
              <p className="text-[10px] text-muted-foreground">Thời gian</p>
              <p className="mt-0.5 text-sm font-medium text-foreground">{simulateDays} ngày</p>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground">Mật độ sự kiện</p>
              <p className="mt-0.5 text-sm font-medium text-foreground">
                {eventsPerDevice} sự kiện/thiết bị
              </p>
            </div>
            <div>
              <p className="text-[10px] text-muted-foreground">Tổng sự kiện ước tính</p>
              <p className="mt-0.5 text-sm font-medium text-foreground">
                {estimatedEvents.toLocaleString()}
              </p>
            </div>
          </div>
        </Section>
      </div>
    );
  };

  // ── Render ────────────────────────────────────────────────────────

  const onNext = () => {
    if (!currentStepValid) return;
    if (step < STEPS.length) setStep(step + 1);
  };

  const onBack = () => {
    if (generating) return;
    if (step > 1) setStep(step - 1);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Setup Wizard"
        description="Cấu hình mạng bệnh viện và tạo dữ liệu mô phỏng để thử nghiệm hệ thống"
        actions={
          <div className="flex h-9 items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 text-xs font-medium text-primary">
            <Wand2 size={14} />
            Bước {step}/{STEPS.length}
          </div>
        }
      />

      {/* Step indicator */}
      <div className="flex justify-center">
        <StepIndicator />
      </div>

      {/* Step content */}
      <div>
        {step === 1 && renderStep1()}
        {step === 2 && renderStep2()}
        {step === 3 && renderStep3()}
        {step === 4 && renderStep4()}
      </div>

      {/* Navigation */}
      {!(step === 4 && (generating || result)) && (
        <div className="flex items-center justify-between rounded-lg border border-border bg-card p-4">
          <button
            onClick={onBack}
            disabled={step === 1 || generating}
            className="flex items-center gap-1.5 rounded-lg border border-border bg-background px-4 py-2 text-xs font-medium text-foreground transition-colors hover:bg-muted disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft size={14} />
            Quay lại
          </button>

          <div className="text-[11px] text-muted-foreground">
            {STEPS[step - 1].description}
          </div>

          {step < 4 ? (
            <button
              onClick={onNext}
              disabled={!currentStepValid}
              className="flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Tiếp theo
              <ChevronRight size={14} />
            </button>
          ) : (
            <button
              onClick={handleGenerate}
              disabled={!currentStepValid || !!error}
              className="flex items-center gap-1.5 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground transition-colors hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Rocket size={14} />
              Bắt đầu tạo dữ liệu
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default AdminSetupWizardPage;
