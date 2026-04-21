import { useState } from 'react';
import { Activity, AlertCircle, Bell, Bug, CheckCircle2, Database, Loader2, RefreshCw, Save, Shield, XCircle, FlaskConical, Clock } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { useHealth, useNvdIntegration, useNvdSave, useNvdSync, useNvdTest, useNvdGenerateAlerts } from '@/hooks/useApi';

type IntegrationStatus = 'connected' | 'disconnected' | 'error';

interface RuntimeCard {
  id: string;
  name: string;
  description: string;
  status: IntegrationStatus;
  summary: string;
  details: Array<{ label: string; value: string }>;
  note?: string;
}

const statusConfig = {
  connected: { label: 'Đã kết nối', icon: CheckCircle2, style: 'text-success bg-success/10' },
  disconnected: { label: 'Chưa kết nối', icon: XCircle, style: 'text-muted-foreground bg-muted' },
  error: { label: 'Lỗi', icon: AlertCircle, style: 'text-critical bg-critical/10' },
};

const AdminIntegrationsPage = () => {
  const [nvdKey, setNvdKey] = useState('');
  const { data: health, isLoading: healthLoading, refetch: refetchHealth } = useHealth();
  const { data: nvdData, isLoading: nvdLoading } = useNvdIntegration();
  const nvdSave = useNvdSave();
  const nvdSync = useNvdSync();
  const nvdTest = useNvdTest();
  const nvdGenerateAlerts = useNvdGenerateAlerts();

  const runtimeCards: RuntimeCard[] = [
    {
      id: 'api-db',
      name: 'API + PostgreSQL',
      description: 'Trạng thái runtime thật của backend và cơ sở dữ liệu.',
      status: health?.database.connected ? 'connected' : health ? 'error' : 'disconnected',
      summary: health?.database.connected ? 'Kết nối database hoạt động' : 'Chưa xác nhận được database',
      details: [
        { label: 'API origin', value: window.location.origin },
        { label: 'Database', value: health?.database.connected ? 'connected' : 'disconnected' },
        { label: 'Total assets', value: String(health?.total_assets ?? 0) },
        { label: 'Last log timestamp', value: health?.last_log_timestamp ?? '—' },
      ],
      note: health?.database.error ?? undefined,
    },
    {
      id: 'zeek-scan',
      name: 'Zeek / Ingestion',
      description: 'Zeek chạy trên host OS — app chỉ đọc log files.',
      status: health?.zeek?.running || health?.scan.running ? 'connected' : health?.scan.error ? 'error' : 'disconnected',
      summary: health?.zeek?.running ? 'Zeek logs detected' : 'No Zeek logs',
      details: [
        { label: 'Zeek sensor', value: health?.zeek?.running ? 'logs available' : 'no logs' },
        { label: 'Ingestion', value: health?.scan.running ? 'running' : 'stopped' },
        { label: 'Mode', value: health?.scan.mode ?? '—' },
        { label: 'Interface', value: health?.scan.interface ?? '—' },
        { label: 'Log dir', value: health?.scan.log_dir ?? '—' },
        { label: 'Logs processed', value: String(health?.scan.logs_processed ?? 0) },
        { label: 'Assets discovered', value: String(health?.scan.assets_discovered ?? 0) },
      ],
      note: health?.zeek?.note ?? health?.scan.error ?? undefined,
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tích hợp"
        description="Chỉ hiển thị trạng thái thật từ backend thay vì dữ liệu giả lập"
        actions={
          <button
            onClick={() => refetchHealth()}
            className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw size={13} /> Làm mới
          </button>
        }
      />

      {(healthLoading || nvdLoading) && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 size={14} className="animate-spin" /> Đang tải trạng thái runtime...
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {runtimeCards.map((card) => {
          const status = statusConfig[card.status];
          const StatusIcon = status.icon;
          const Icon = card.id === 'api-db' ? Database : Activity;

          return (
            <div key={card.id} className="rounded-lg border border-border bg-card overflow-hidden">
              <div className="flex items-start gap-3 border-b border-border bg-muted/20 p-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Icon size={18} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-foreground">{card.name}</span>
                    <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ${status.style}`}>
                      <StatusIcon size={10} /> {status.label}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">{card.description}</p>
                  <p className="mt-2 text-xs text-foreground">{card.summary}</p>
                  {card.note && <p className="mt-1 text-[11px] text-critical">{card.note}</p>}
                </div>
              </div>
              <div className="grid gap-2 p-4 sm:grid-cols-2">
                {card.details.map((item) => (
                  <div key={item.label} className="rounded-md border border-border bg-card px-3 py-2">
                    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{item.label}</div>
                    <div className="mt-1 break-all font-mono text-xs text-foreground">{item.value}</div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Vulnerability Sources ─────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Bug size={15} className="text-primary" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-foreground">Vulnerability Sources</h3>
          <span className="text-[11px] text-muted-foreground">Nguồn CVE ghép với CPE suy luận của từng thiết bị</span>
        </div>

      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="flex items-center gap-3 border-b border-border bg-muted/20 p-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400">
            <Shield size={18} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-foreground">NVD (National Vulnerability Database)</span>
              {nvdData?.configured ? (
                <span className="inline-flex items-center gap-1 rounded-md bg-success/10 px-1.5 py-0.5 text-[10px] font-medium text-success">
                  <CheckCircle2 size={10} /> Đã cấu hình
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                  <XCircle size={10} /> Chưa cấu hình
                </span>
              )}
            </div>
            <p className="text-[11px] text-muted-foreground">Tra cứu CVE và điểm CVSS cho các CPE đã suy luận</p>
          </div>
        </div>

        <div className="space-y-4 p-4">
          {(nvdSave.error || nvdSync.error || nvdTest.error || nvdGenerateAlerts.error) && (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2.5 text-xs text-destructive">
              <AlertCircle size={13} />
              {nvdSave.error instanceof Error
                ? nvdSave.error.message
                : nvdSync.error instanceof Error
                ? nvdSync.error.message
                : nvdTest.error instanceof Error
                ? nvdTest.error.message
                : nvdGenerateAlerts.error instanceof Error
                ? nvdGenerateAlerts.error.message
                : 'Lỗi'}
            </div>
          )}

          {nvdSync.isSuccess && (
            <div className="flex items-center gap-2 rounded-lg border border-success/30 bg-success/10 px-3 py-2.5 text-xs text-success">
              <CheckCircle2 size={13} /> Đồng bộ NVD đã được kích hoạt.
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="sm:col-span-2">
              <label className="mb-1.5 block text-xs font-medium text-foreground">NVD API Key</label>
              <input
                type="password"
                value={nvdKey}
                onChange={(e) => setNvdKey(e.target.value)}
                placeholder="Nhập API key từ NVD"
                className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              />
              <p className="mt-1 text-[11px] text-muted-foreground">
                Lần đồng bộ gần nhất: {nvdData?.last_sync_at ?? 'chưa có'}
              </p>
            </div>

            <div className="flex flex-wrap items-end gap-2">
              <button
                onClick={() => nvdSave.mutate(nvdKey)}
                disabled={!nvdKey || nvdSave.isPending}
                className="flex flex-1 min-w-[110px] items-center justify-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
              >
                {nvdSave.isPending ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
                Lưu key
              </button>
              <button
                onClick={() => nvdSync.mutate()}
                disabled={!nvdData?.configured || nvdSync.isPending}
                className="flex flex-1 min-w-[110px] items-center justify-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs font-medium text-foreground disabled:cursor-not-allowed disabled:opacity-50"
              >
                {nvdSync.isPending ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
                Đồng bộ
              </button>
              <button
                onClick={() => nvdTest.mutate()}
                disabled={!nvdData?.configured || nvdTest.isPending}
                className="flex flex-1 min-w-[110px] items-center justify-center gap-2 rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-2 text-xs font-medium text-blue-400 hover:bg-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                title="Kiểm tra nhanh 5 CPE đầu tiên"
              >
                {nvdTest.isPending ? <Loader2 size={13} className="animate-spin" /> : <FlaskConical size={13} />}
                Test CVE
              </button>
              <button
                onClick={() => nvdGenerateAlerts.mutate()}
                disabled={!nvdData?.configured || nvdGenerateAlerts.isPending}
                className="flex flex-1 min-w-[110px] items-center justify-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-400 hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                title="Tạo cảnh báo từ CVE đã liên kết (không sync lại)"
              >
                {nvdGenerateAlerts.isPending ? <Loader2 size={13} className="animate-spin" /> : <Bell size={13} />}
                Tạo cảnh báo
              </button>
            </div>
          </div>

          {nvdGenerateAlerts.data && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
              <div className="mb-3 flex items-center gap-2">
                <Bell size={14} className="text-amber-400" />
                <span className="text-xs font-semibold text-foreground">Kết quả Tạo cảnh báo</span>
                {nvdGenerateAlerts.data.alerts_created > 0 ? (
                  <span className="inline-flex items-center gap-1 rounded-md bg-success/10 px-1.5 py-0.5 text-[10px] font-medium text-success">
                    <CheckCircle2 size={10} /> {nvdGenerateAlerts.data.alerts_created} cảnh báo mới
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                    Không có mới
                  </span>
                )}
              </div>
              <div className="grid gap-2 sm:grid-cols-4">
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Cảnh báo mới tạo</div>
                  <div className="mt-1 text-sm font-semibold text-amber-400">{nvdGenerateAlerts.data.alerts_created}</div>
                </div>
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Chưa có cảnh báo</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">{nvdGenerateAlerts.data.rows_found ?? '—'}</div>
                </div>
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Liên kết CVE tổng</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">{nvdGenerateAlerts.data.total_asset_vuln_links}</div>
                </div>
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Cảnh báo CVE hiện có</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">{nvdGenerateAlerts.data.existing_vuln_alerts}</div>
                </div>
              </div>
              <p className="mt-2 text-[11px] text-muted-foreground">{nvdGenerateAlerts.data.message}</p>
            </div>
          )}

          {nvdTest.data && (
            <div className="rounded-lg border border-blue-500/30 bg-blue-500/5 p-4">
              <div className="mb-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FlaskConical size={14} className="text-blue-400" />
                  <span className="text-xs font-semibold text-foreground">Kết quả Test CVE</span>
                  <span className="inline-flex items-center gap-1 rounded-md bg-success/10 px-1.5 py-0.5 text-[10px] font-medium text-success">
                    <CheckCircle2 size={10} /> Thành công
                  </span>
                </div>
                <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <Clock size={11} />
                  {nvdTest.data.elapsed_seconds}s
                </div>
              </div>

              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">CPE đã kiểm tra</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">
                    {nvdTest.data.cpes_checked}
                    <span className="ml-1 text-[11px] font-normal text-muted-foreground">/ {nvdTest.data.total_cpes}</span>
                  </div>
                </div>
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">CVE tìm thấy</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">{nvdTest.data.cves_found}</div>
                </div>
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">Tài sản liên kết</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">{nvdTest.data.assets_linked}</div>
                </div>
                <div className="rounded-md border border-border bg-card px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">API Key</div>
                  <div className="mt-1 text-sm font-semibold text-foreground">
                    {nvdTest.data.api_key_used ? (
                      <span className="text-success">đã dùng</span>
                    ) : (
                      <span className="text-amber-400">anonymous</span>
                    )}
                  </div>
                </div>
              </div>

              {nvdTest.data.sample_cves.length > 0 ? (
                <div className="mt-3 space-y-1.5">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    CVE mẫu ({nvdTest.data.sample_cves.length})
                  </div>
                  {nvdTest.data.sample_cves.map((cve, i) => {
                    const sev = (cve.severity || '').toLowerCase();
                    const sevStyle =
                      sev === 'critical'
                        ? 'bg-critical/10 text-critical'
                        : sev === 'high'
                        ? 'bg-rose-500/10 text-rose-400'
                        : sev === 'medium'
                        ? 'bg-amber-500/10 text-amber-400'
                        : sev === 'low'
                        ? 'bg-emerald-500/10 text-emerald-400'
                        : 'bg-muted text-muted-foreground';
                    return (
                      <div
                        key={`${cve.cve_id}-${i}`}
                        className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-[11px]"
                      >
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono font-semibold text-blue-400 hover:underline"
                        >
                          {cve.cve_id}
                        </a>
                        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${sevStyle}`}>
                          {cve.severity || 'N/A'}
                        </span>
                        <span className="font-mono text-foreground">CVSS {cve.cvss_score.toFixed(1)}</span>
                        {cve.published && (
                          <span className="font-mono text-[10px] text-muted-foreground">{cve.published}</span>
                        )}
                        <span className="break-all font-mono text-muted-foreground">{cve.cpe}</span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-[11px] text-muted-foreground">
                  Không tìm thấy CVE nào cho mẫu CPE đã kiểm tra. Có thể các CPE này chưa có CVE khớp trên NVD.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      </div>
    </div>
  );
};

export default AdminIntegrationsPage;