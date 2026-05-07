import { Monitor, Network, Globe, Lock, TrendingUp, RefreshCw, Cpu, Play, Square, Database, ShieldAlert, AlertTriangle, Info, BarChart3, Bug } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, BarChart, Bar } from 'recharts';
import StatCard from '@/components/widgets/StatCard';
import PageHeader from '@/components/widgets/PageHeader';
import LiveThreatStrip from '@/components/xdr/LiveThreatStrip';
import SocControlPanel from '@/components/soc/SocControlPanel';
import { StatCardsSkeleton, ChartSkeleton, TableSkeleton } from '@/components/widgets/Skeletons';
import { useChartTheme } from '@/hooks/useChartTheme';
import {
  useStats, useInferenceSummary, useScanStatus, useHealth,
  useConfidenceDistribution, useAnomalySummary, useAssets,
  useAlertCounts,
} from '@/hooks/useApi';
import { useNavigate } from 'react-router-dom';
import { format } from 'date-fns';

// ─── Confidence cap — inference system, never 100% ──────────────────────────
const CONFIDENCE_CAP = 95;
const capConf = (raw: number) => Math.min(raw, CONFIDENCE_CAP);

const fmtBytes = (b: number) => {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
};

const DEVICE_TYPE_COLORS: Record<string, string> = {
  IoMT:        '#f43f5e',
  IoT:         '#f59e0b',
  Network:     '#3b82f6',
  Workstation: '#8b5cf6',
  Server:      '#06b6d4',
  Scanner:     '#f97316',
  Printer:     '#10b981',
  'IP Camera': '#ec4899',
  Unknown:     '#6b7280',
};

const SHOW_DEVICE_TYPES = ['IoMT', 'IoT', 'Workstation', 'Server', 'Network', 'Printer', 'IP Camera', 'Unknown'] as const;

const CONFIDENCE_BUCKET_COLORS = {
  high:     '#10b981',
  medium:   '#3b82f6',
  low:      '#f59e0b',
  very_low: '#ef4444',
};

const DashboardPage = () => {
  const navigate = useNavigate();
  const chart = useChartTheme();
  const { data: stats, isLoading, isError, refetch } = useStats();
  const { data: inferenceSummary = [] } = useInferenceSummary();
  const { data: confDist } = useConfidenceDistribution();
  const { data: anomalySummary } = useAnomalySummary();
  const { data: alertCounts } = useAlertCounts();
  const { data: health } = useHealth();
  const { data: scanStatus } = useScanStatus();
  // Fetch 50 assets with lowest confidence first — we surface the ones that
  // have CVEs attached for the analyst's attention.
  const { data: riskPool } = useAssets({ has_vuln: true, sort: 'max_cvss_desc', limit: 1000 });
  const scanRunning = scanStatus?.running ?? false;

  if (isLoading || !stats) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" description="Asset Intelligence & Behavior Analysis" />
        <StatCardsSkeleton />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <ChartSkeleton />
          <ChartSkeleton />
        </div>
        <TableSkeleton rows={5} cols={5} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" description="Asset Intelligence & Behavior Analysis" />
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-6 text-center">
          <p className="text-sm font-medium text-destructive">Không thể tải dữ liệu từ máy chủ.</p>
          <button onClick={() => refetch()} className="mt-3 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
            Thử lại
          </button>
        </div>
      </div>
    );
  }

  const totalAssets = Number(stats.assets.total);
  const activeAssets = Number(stats.assets.active);
  const totalConns = Number(stats.connections.total);
  const totalDns = Number(stats.dns.total);
  const totalTls = Number(stats.tls.total);
  const bytesOut = Number(stats.connections.total_bytes_sent);
  const bytesIn = Number(stats.connections.total_bytes_recv);

  const trafficData = stats.trafficByHour.map(h => ({
    time: format(new Date(h.hour), 'HH:mm'),
    outbound: Math.round(Number(h.bytes_out) / 1024),
    inbound: Math.round(Number(h.bytes_in) / 1024),
    connections: Number(h.conn_count),
  }));

  // Device type pie
  const typeCounts: Record<string, number> = {};
  inferenceSummary.forEach(r => {
    const type = r.device_type ?? 'Unknown';
    const bucket = (SHOW_DEVICE_TYPES as readonly string[]).includes(type) ? type : 'Unknown';
    typeCounts[bucket] = (typeCounts[bucket] ?? 0) + Number(r.count);
  });
  const deviceTotal = Object.values(typeCounts).reduce((s, v) => s + v, 0);
  const devicePieData = SHOW_DEVICE_TYPES
    .filter(t => (typeCounts[t] ?? 0) > 0)
    .map(t => ({
      name: t,
      value: typeCounts[t],
      pct: deviceTotal > 0 ? Math.round((typeCounts[t] / deviceTotal) * 1000) / 10 : 0,
      fill: DEVICE_TYPE_COLORS[t] ?? '#6b7280',
    }));

  // Confidence histogram
  const confHistData = confDist
    ? [
        { name: 'Cao (≥90)', value: confDist.high, fill: CONFIDENCE_BUCKET_COLORS.high },
        { name: 'TB (60–89)', value: confDist.medium, fill: CONFIDENCE_BUCKET_COLORS.medium },
        { name: 'Thấp (30–59)', value: confDist.low, fill: CONFIDENCE_BUCKET_COLORS.low },
        { name: 'Rất thấp (<30)', value: confDist.very_low, fill: CONFIDENCE_BUCKET_COLORS.very_low },
      ]
    : [];

  // Anomaly counts
  const anomTotal = anomalySummary?.total ?? 0;
  const anomAffected = anomalySummary?.affected_assets ?? 0;

  // Critical CVE count — vulnerability alerts with severity=critical, excluding
  // those analysts have marked as false positive on the Alerts page.
  const criticalCveCount = alertCounts?.critical_vulns_active ?? 0;
  const highAlertCount = alertCounts?.by_severity?.find(
    s => s.severity.toLowerCase() === 'high',
  )?.count ?? 0;

  // Top CVE assets — assets with CVEs attached, ordered by max CVSS then count.
  const topCveAssets = riskPool?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Asset Intelligence & Behavior Analysis"
        actions={
          <button onClick={() => refetch()} className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <RefreshCw size={13} /> Làm mới
          </button>
        }
      />

      {/* ── Inference disclaimer ───────────────────────────────────────── */}
      <div className="flex items-center gap-2 rounded-lg border border-blue-500/20 bg-blue-500/5 px-4 py-2.5 text-[11px] text-blue-300/80">
        <Info size={14} className="shrink-0 text-blue-400" />
        <span>
          Đây là hệ thống suy luận thụ động — tất cả phân loại dựa trên hành vi mạng quan sát được. Độ tin cậy là ước tính, tối đa {CONFIDENCE_CAP}%. Không phải ground truth.
        </span>
      </div>

      {/* ── SOC Control Panel ───────────────────────────────────────────── */}
      <SocControlPanel />

      {/* ── Live Threat Activity (XDR overlay) ──────────────────────────── */}
      <LiveThreatStrip />

      {/* ── KPI tiles ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <StatCard title="Tổng tài sản" value={totalAssets} icon={Monitor} trend={`${activeAssets} hoạt động gần đây`} />
        <StatCard title="Kết nối" value={totalConns.toLocaleString()} icon={Network} variant="info" trend={`${fmtBytes(bytesOut)} gửi / ${fmtBytes(bytesIn)} nhận`} />

        {/* Critical CVEs */}
        <div className="rounded-lg border border-border bg-card p-4 flex items-center gap-3">
          <div className={`rounded-lg p-2 ${criticalCveCount > 0 ? 'bg-rose-500/10' : 'bg-muted/30'}`}>
            <ShieldAlert size={16} className={criticalCveCount > 0 ? 'text-rose-400' : 'text-muted-foreground'} />
          </div>
          <div>
            <p className="text-xs font-semibold text-foreground">Cảnh báo nghiêm trọng</p>
            <div className="flex items-center gap-2">
              <span className={`text-lg font-bold font-mono ${criticalCveCount > 0 ? 'text-rose-400' : 'text-muted-foreground'}`}>{criticalCveCount}</span>
              {highAlertCount > 0 && <span className="text-[10px] text-amber-400">+{highAlertCount} cao</span>}
            </div>
          </div>
        </div>

      </div>

      {/* ── Charts Row 1: Device pie + Traffic ────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Device type pie chart */}
        <div className="rounded-lg border border-border bg-card p-5">
          <div className="mb-4 flex items-center gap-2">
            <Cpu size={15} className="text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Phân loại thiết bị (Inference)</h3>
          </div>
          {devicePieData.length === 0 ? (
            <div className="flex h-[220px] items-center justify-center text-xs text-muted-foreground">
              Chưa có dữ liệu phân loại thiết bị
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={devicePieData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={3} dataKey="value" stroke="none">
                    {devicePieData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={chart.tooltipStyle}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const d = payload[0].payload;
                      return (
                        <div style={chart.tooltipStyle} className="rounded-md px-3 py-2 text-xs shadow-lg">
                          <p className="font-semibold mb-1" style={{ color: d.fill }}>{d.name}</p>
                          <p className="text-foreground">{d.value.toLocaleString()} thiết bị</p>
                          <p className="text-muted-foreground">{d.pct}% tổng số</p>
                        </div>
                      );
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5">
                {devicePieData.map(d => (
                  <div key={d.name} className="flex items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="h-2.5 w-2.5 flex-shrink-0 rounded-full" style={{ backgroundColor: d.fill }} />
                      <span className="truncate text-foreground font-medium">{d.name}</span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 font-mono">
                      <span className="text-foreground">{d.value.toLocaleString()}</span>
                      <span className="text-muted-foreground w-10 text-right">{d.pct < 1 && d.pct > 0 ? `${d.pct.toFixed(1)}%` : `${d.pct}%`}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Traffic chart */}
        <div className="rounded-lg border border-border bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Lưu lượng mạng</h3>
              <p className="text-[11px] text-muted-foreground">KB — 24 giờ qua</p>
            </div>
            <TrendingUp size={16} className="text-success" />
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={trafficData}>
              <defs>
                <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={chart.colors.primary} stopOpacity={0.2} />
                  <stop offset="100%" stopColor={chart.colors.primary} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={chart.colors.success} stopOpacity={0.2} />
                  <stop offset="100%" stopColor={chart.colors.success} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
              <XAxis dataKey="time" stroke={chart.axisStroke} tick={chart.axisTick} />
              <YAxis stroke={chart.axisStroke} tick={chart.axisTick} />
              <Tooltip contentStyle={chart.tooltipStyle} formatter={(v: number) => v.toLocaleString() + ' KB'} />
              <Legend wrapperStyle={chart.legendStyle} />
              <Area type="monotone" dataKey="inbound" name="Đến" stroke={chart.colors.primary} fill="url(#inGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="outbound" name="Đi" stroke={chart.colors.success} fill="url(#outGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Top CVE Assets ────────────────────────────────────────────── */}
      <div className="rounded-lg border border-border bg-card p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bug size={15} className="text-rose-400" />
            <h3 className="text-sm font-semibold text-foreground">Tài sản có CVE</h3>
            <span className="text-[11px] text-muted-foreground">Thiết bị đã map CVE theo CPE — ưu tiên xem xét</span>
          </div>
          <span className="text-[10px] text-muted-foreground">Sắp xếp theo CVSS tối đa</span>
        </div>
        {topCveAssets.length === 0 ? (
          <div className="flex h-[160px] items-center justify-center text-xs text-muted-foreground">
            Chưa có tài sản nào được map CVE. Vào Tích hợp → cấu hình NVD và bấm Đồng bộ.
          </div>
        ) : (
          <div className="h-[260px] overflow-y-scroll overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-card">
                <tr className="border-b border-border text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  <th className="pb-3 pr-4 pt-1">IP</th>
                  <th className="pb-3 pr-4 pt-1">Loại thiết bị</th>
                  <th className="pb-3 pr-4 pt-1">OS / Vendor</th>
                  <th className="pb-3 pr-4 pt-1">Số CVE</th>
                  <th className="pb-3 pr-4 pt-1">CVSS tối đa</th>
                  <th className="pb-3 pt-1">Tin cậy</th>
                </tr>
              </thead>
              <tbody>
                {topCveAssets.map(asset => {
                  const dt = asset.deviceType ?? 'Unknown';
                  const conf = capConf(Number(asset.confidence ?? asset.confidence_score ?? 0));
                  const cvss = asset.max_cvss ?? 0;
                  const cvssCls =
                    cvss >= 9 ? 'text-rose-300 bg-rose-500/15 border border-rose-500/30'
                    : cvss >= 7 ? 'text-amber-300 bg-amber-500/15 border border-amber-500/30'
                    : cvss >= 4 ? 'text-blue-300 bg-blue-500/15 border border-blue-500/30'
                    : 'text-emerald-300 bg-emerald-500/15 border border-emerald-500/30';
                  return (
                    <tr
                      key={asset.id}
                      className="border-b border-border/30 cursor-pointer transition-colors hover:bg-accent/50"
                      onClick={() => navigate(`/assets/${asset.id}`)}
                    >
                      <td className="py-2.5 pr-4 font-mono text-xs text-primary">{asset.ip || '—'}</td>
                      <td className="py-2.5 pr-4 text-xs text-foreground">{dt}</td>
                      <td className="py-2.5 pr-4 text-[11px] text-muted-foreground">{asset.vendor || '—'}</td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-rose-300">{asset.vuln_count ?? 0}</td>
                      <td className="py-2.5 pr-4">
                        <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold font-mono ${cvssCls}`}>
                          {cvss.toFixed(1)}
                        </span>
                      </td>
                      <td className="py-2.5 font-mono text-[11px] text-muted-foreground">{conf}%</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Charts Row 2: Confidence histogram ────────────────────────── */}
      <div className="grid grid-cols-1 gap-4">
        {/* Confidence Distribution histogram */}
        <div className="rounded-lg border border-border bg-card p-5">
          <div className="mb-4 flex items-center gap-2">
            <BarChart3 size={15} className="text-primary" />
            <div>
              <h3 className="text-sm font-semibold text-foreground">Phân bố độ tin cậy (ước tính)</h3>
              <p className="text-[10px] text-muted-foreground">Tối đa {CONFIDENCE_CAP}% — hệ thống suy luận</p>
            </div>
          </div>
          {confHistData.length === 0 ? (
            <div className="flex h-[180px] items-center justify-center text-xs text-muted-foreground">
              Chưa có dữ liệu
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={confHistData} barCategoryGap="20%">
                  <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                  <XAxis dataKey="name" stroke={chart.axisStroke} tick={{ fontSize: 10, fill: chart.axisStroke as string }} />
                  <YAxis stroke={chart.axisStroke} tick={chart.axisTick} allowDecimals={false} />
                  <Tooltip
                    contentStyle={chart.tooltipStyle}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const d = payload[0].payload;
                      return (
                        <div style={chart.tooltipStyle} className="rounded-md px-3 py-2 text-xs shadow-lg">
                          <p className="font-semibold mb-1" style={{ color: d.fill }}>{d.name}</p>
                          <p className="text-foreground">{d.value} tài sản</p>
                        </div>
                      );
                    }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {confHistData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-3">
                {confHistData.map(d => (
                  <div key={d.name} className="flex items-center gap-1.5 text-[11px]">
                    <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: d.fill }} />
                    <span className="text-muted-foreground">{d.name}:</span>
                    <span className="font-mono font-medium text-foreground">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

export default DashboardPage;
