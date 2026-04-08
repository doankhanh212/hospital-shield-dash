import { Monitor, Cpu, HelpCircle, Bug, ShieldAlert } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import StatCard from '@/components/widgets/StatCard';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import { assets, trafficData, deviceTypeDistribution } from '@/data/mockData';
import { useNavigate } from 'react-router-dom';

const DashboardPage = () => {
  const navigate = useNavigate();
  const iotDevices = assets.filter(a => a.deviceType === 'IoT' || a.deviceType === 'IoMT');
  const unknownDevices = assets.filter(a => a.deviceType === 'Chưa xác định');
  const vulnDevices = assets.filter(a => a.vulnerabilities.length > 0);
  const topRisk = [...assets].sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-foreground">Dashboard</h2>
        <p className="text-sm text-muted-foreground">Tổng quan an ninh mạng bệnh viện</p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Tổng số tài sản" value={assets.length} icon={Monitor} trend="+2 tuần này" />
        <StatCard title="Thiết bị IoT/IoMT" value={iotDevices.length} icon={Cpu} trend={`${iotDevices.length} thiết bị y tế`} />
        <StatCard title="Chưa xác định" value={unknownDevices.length} icon={HelpCircle} variant="warning" trend="Cần kiểm tra" />
        <StatCard title="Có lỗ hổng" value={vulnDevices.length} icon={Bug} variant="critical" trend="2 Critical" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Device type chart */}
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 text-sm font-semibold text-foreground">Phân loại thiết bị</h3>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={deviceTypeDistribution} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" stroke="none">
                {deviceTypeDistribution.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: 'hsl(222 44% 8%)', border: '1px solid hsl(222 30% 16%)', borderRadius: '8px', color: 'hsl(210 40% 92%)' }} />
              <Legend wrapperStyle={{ fontSize: '12px', color: 'hsl(215 20% 55%)' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Traffic chart */}
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 text-sm font-semibold text-foreground">Lưu lượng mạng (Mbps)</h3>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222 30% 16%)" />
              <XAxis dataKey="time" stroke="hsl(215 20% 55%)" tick={{ fontSize: 11 }} />
              <YAxis stroke="hsl(215 20% 55%)" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: 'hsl(222 44% 8%)', border: '1px solid hsl(222 30% 16%)', borderRadius: '8px', color: 'hsl(210 40% 92%)' }} />
              <Legend wrapperStyle={{ fontSize: '12px' }} />
              <Line type="monotone" dataKey="inbound" name="Đến" stroke="hsl(210 100% 52%)" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="outbound" name="Đi" stroke="hsl(142 71% 45%)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top risk devices */}
      <div className="rounded-lg border border-border bg-card p-5">
        <h3 className="mb-4 text-sm font-semibold text-foreground flex items-center gap-2">
          <ShieldAlert size={16} className="text-critical" />
          Top thiết bị có rủi ro cao
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
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
                  className="border-b border-border/50 cursor-pointer transition-colors hover:bg-accent/50"
                  onClick={() => navigate(`/assets/${asset.id}`)}
                >
                  <td className="py-3 pr-4 font-mono text-xs text-primary">{asset.ip}</td>
                  <td className="py-3 pr-4">{asset.vendor}</td>
                  <td className="py-3 pr-4">{asset.deviceType}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-16 rounded-full bg-muted overflow-hidden">
                        <div
                          className={`h-full rounded-full ${asset.riskScore >= 80 ? 'bg-critical' : asset.riskScore >= 50 ? 'bg-warning' : 'bg-success'}`}
                          style={{ width: `${asset.riskScore}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono">{asset.riskScore}</span>
                    </div>
                  </td>
                  <td className="py-3 pr-4">
                    {asset.vulnerabilities.length > 0 ? (
                      <SeverityBadge severity={asset.vulnerabilities[0].severity} />
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="py-3">
                    <span className={`inline-flex items-center gap-1.5 text-xs ${asset.status === 'online' ? 'text-success' : asset.status === 'offline' ? 'text-muted-foreground' : 'text-warning'}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${asset.status === 'online' ? 'bg-success animate-pulse-glow' : asset.status === 'offline' ? 'bg-muted-foreground' : 'bg-warning'}`} />
                      {asset.status === 'online' ? 'Hoạt động' : asset.status === 'offline' ? 'Ngoại tuyến' : 'Không rõ'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage;
