import { useState, useEffect } from 'react';
import { networkFlows } from '@/data/mockData';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Network, AlertTriangle, ArrowRightLeft } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { ChartSkeleton, TableSkeleton } from '@/components/widgets/Skeletons';
import { useChartTheme } from '@/hooks/useChartTheme';

const portStats = networkFlows.reduce((acc, f) => {
  if (f.port > 0) {
    const key = `${f.port}/${f.protocol}`;
    acc[key] = (acc[key] || 0) + f.packets;
  }
  return acc;
}, {} as Record<string, number>);

const topPorts = Object.entries(portStats)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 8)
  .map(([name, packets]) => ({ name, packets }));

const anomalies = [
  { id: 1, description: 'Camera Hikvision kết nối đến IP nước ngoài', source: '10.0.2.15', destination: '203.0.113.50:8080', severity: 'Critical' as const },
  { id: 2, description: 'Thiết bị chưa xác định quét port trên toàn mạng', source: '10.0.4.100', destination: '10.0.0.0/16', severity: 'Critical' as const },
  { id: 3, description: 'Lưu lượng DICOM bất thường vào ban đêm', source: '10.0.1.20', destination: '10.0.1.50', severity: 'Medium' as const },
];

const NetworkPage = () => {
  const chart = useChartTheme();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 600);
    return () => clearTimeout(t);
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Hành vi mạng" description="Phân tích luồng kết nối và phát hiện bất thường" />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <TableSkeleton rows={6} cols={4} />
          <ChartSkeleton />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Hành vi mạng" description="Phân tích luồng kết nối và phát hiện bất thường" />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
            <ArrowRightLeft size={15} className="text-primary" />
            Luồng kết nối mạng
          </h3>
          <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
            {networkFlows.map((f, i) => (
              <div key={i} className="flex items-center justify-between rounded-lg border border-border/30 bg-muted/20 px-3 py-2 text-xs transition-colors hover:bg-accent/30">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-primary whitespace-nowrap">{f.source}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono whitespace-nowrap">{f.destination}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0 ml-3">
                  <span className="rounded-md bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">{f.protocol}</span>
                  <span className="text-muted-foreground font-mono">:{f.port}</span>
                  <span className="text-muted-foreground">{(f.bytes / 1048576).toFixed(1)}MB</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
            <Network size={15} className="text-primary" />
            Top port sử dụng
          </h3>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={topPorts} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
              <XAxis type="number" stroke={chart.axisStroke} tick={chart.axisTick} />
              <YAxis type="category" dataKey="name" stroke={chart.axisStroke} tick={chart.axisTick} width={100} />
              <Tooltip contentStyle={chart.tooltipStyle} />
              <Bar dataKey="packets" fill={chart.colors.primary} radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
          <AlertTriangle size={15} className="text-warning" />
          Phát hiện bất thường
        </h3>
        <div className="space-y-2">
          {anomalies.map(a => (
            <div key={a.id} className={`rounded-lg border p-4 transition-colors hover:bg-accent/20 ${a.severity === 'Critical' ? 'border-critical/20' : 'border-warning/20'}`}>
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">{a.description}</p>
                  <p className="mt-1 text-xs text-muted-foreground font-mono">{a.source} → {a.destination}</p>
                </div>
                <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${a.severity === 'Critical' ? 'border-critical/30 bg-critical/10 text-critical' : 'border-medium/30 bg-medium/10 text-medium'}`}>
                  {a.severity}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default NetworkPage;
