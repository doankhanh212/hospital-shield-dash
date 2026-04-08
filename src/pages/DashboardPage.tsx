import { useState, useEffect } from 'react';
import { Monitor, Cpu, HelpCircle, Bug, ShieldAlert, AlertTriangle, TrendingUp } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import StatCard from '@/components/widgets/StatCard';
import PageHeader from '@/components/widgets/PageHeader';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import { StatCardsSkeleton, ChartSkeleton, TableSkeleton } from '@/components/widgets/Skeletons';
import { useChartTheme } from '@/hooks/useChartTheme';
import { assets, trafficData, deviceTypeDistribution, alerts } from '@/data/mockData';
import { useNavigate } from 'react-router-dom';

const DashboardPage = () => {
  const navigate = useNavigate();
  const chart = useChartTheme();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 800);
    return () => clearTimeout(t);
  }, []);

  const iotDevices = assets.filter(a => a.deviceType === 'IoT' || a.deviceType === 'IoMT');
  const unknownDevices = assets.filter(a => a.deviceType === 'Chưa xác định');
  const vulnDevices = assets.filter(a => a.vulnerabilities.length > 0);
  const topRisk = [...assets].sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);
  const recentAlerts = alerts.filter(a => a.status !== 'resolved').slice(0, 3);

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" description="Tổng quan an ninh mạng bệnh viện" />
        <StatCardsSkeleton />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <ChartSkeleton />
          <ChartSkeleton />
        </div>
        <TableSkeleton rows={5} cols={6} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Tổng quan an ninh mạng bệnh viện" />

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Tổng tài sản" value={assets.length} icon={Monitor} trend="+2 tuần này" />
        <StatCard title="IoT / IoMT" value={iotDevices.length} icon={Cpu} variant="info" trend={`${iotDevices.length} thiết bị y tế`} />
        <StatCard title="Chưa xác định" value={unknownDevices.length} icon={HelpCircle} variant="warning" trend="Cần kiểm tra" />
        <StatCard title="Có lỗ hổng" value={vulnDevices.length} icon={Bug} variant="critical" trend="2 Critical" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <div className="xl:col-span-2 rounded-lg border border-border bg-card p-5">
          <h3 className="mb-1 text-sm font-semibold text-foreground">Phân loại thiết bị</h3>
          <p className="mb-4 text-[11px] text-muted-foreground">Tổng: {assets.length} thiết bị</p>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={deviceTypeDistribution} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={3} dataKey="value" stroke="none">
                {deviceTypeDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip contentStyle={chart.tooltipStyle} />
              <Legend wrapperStyle={chart.legendStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="xl:col-span-3 rounded-lg border border-border bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">Lưu lượng mạng</h3>
              <p className="text-[11px] text-muted-foreground">Mbps — 24 giờ qua</p>
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
              <Tooltip contentStyle={chart.tooltipStyle} />
              <Legend wrapperStyle={chart.legendStyle} />
              <Area type="monotone" dataKey="inbound" name="Đến" stroke={chart.colors.primary} fill="url(#inGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="outbound" name="Đi" stroke={chart.colors.success} fill="url(#outGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bottom row: risk table + recent alerts */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2 rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 text-sm font-semibold text-foreground flex items-center gap-2">
            <ShieldAlert size={15} className="text-critical" />
            Top thiết bị rủi ro cao
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  <th className="pb-3 pr-4">IP</th>
                  <th className="pb-3 pr-4">Vendor</th>
                  <th className="pb-3 pr-4">Loại</th>
                  <th className="pb-3 pr-4">Rủi ro</th>
                  <th className="pb-3 pr-4">Lỗ hổng</th>
                  <th className="pb-3">Trạng thái</th>
                </tr>
              </thead>
              <tbody>
                {topRisk.map(asset => (
                  <tr
                    key={asset.id}
                    className="border-b border-border/30 cursor-pointer transition-colors hover:bg-accent/50"
                    onClick={() => navigate(`/assets/${asset.id}`)}
                  >
                    <td className="py-2.5 pr-4 font-mono text-xs text-primary">{asset.ip}</td>
                    <td className="py-2.5 pr-4 text-xs">{asset.vendor}</td>
                    <td className="py-2.5 pr-4 text-xs">{asset.deviceType}</td>
                    <td className="py-2.5 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-14 rounded-full bg-muted overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${asset.riskScore >= 80 ? 'bg-critical' : asset.riskScore >= 50 ? 'bg-warning' : 'bg-success'}`}
                            style={{ width: `${asset.riskScore}%` }}
                          />
                        </div>
                        <span className="text-[11px] font-mono font-semibold">{asset.riskScore}</span>
                      </div>
                    </td>
                    <td className="py-2.5 pr-4">
                      {asset.vulnerabilities.length > 0 ? (
                        <SeverityBadge severity={asset.vulnerabilities[0].severity} />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="py-2.5">
                      <span className={`inline-flex items-center gap-1.5 text-[11px] ${asset.status === 'online' ? 'text-success' : asset.status === 'offline' ? 'text-muted-foreground' : 'text-warning'}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${asset.status === 'online' ? 'bg-success animate-pulse-glow' : asset.status === 'offline' ? 'bg-muted-foreground' : 'bg-warning'}`} />
                        {asset.status === 'online' ? 'Online' : asset.status === 'offline' ? 'Offline' : 'N/A'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent alerts */}
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 text-sm font-semibold text-foreground flex items-center gap-2">
            <AlertTriangle size={15} className="text-warning" />
            Cảnh báo gần đây
          </h3>
          <div className="space-y-3">
            {recentAlerts.map(alert => (
              <div key={alert.id} className="rounded-md border border-border/50 p-3 transition-colors hover:bg-accent/30 cursor-pointer" onClick={() => navigate('/alerts')}>
                <div className="flex items-start gap-2">
                  <SeverityBadge severity={alert.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-foreground line-clamp-2">{alert.message}</p>
                    <p className="mt-1 text-[10px] text-muted-foreground font-mono">{alert.timestamp}</p>
                  </div>
                </div>
              </div>
            ))}
            <button onClick={() => navigate('/alerts')} className="w-full rounded-md bg-accent/50 py-2 text-[11px] font-medium text-muted-foreground hover:text-foreground transition-colors">
              Xem tất cả cảnh báo →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
