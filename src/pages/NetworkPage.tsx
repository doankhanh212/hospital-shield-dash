import { networkFlows } from '@/data/mockData';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Network, AlertTriangle, ArrowRightLeft } from 'lucide-react';

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
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-foreground">Hành vi mạng</h2>
        <p className="text-sm text-muted-foreground">Phân tích luồng kết nối và phát hiện bất thường</p>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Network flows */}
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
            <ArrowRightLeft size={16} className="text-primary" />
            Luồng kết nối mạng
          </h3>
          <div className="space-y-2 max-h-[360px] overflow-y-auto pr-2">
            {networkFlows.map((f, i) => (
              <div key={i} className="flex items-center justify-between rounded-md border border-border/50 bg-muted/30 px-3 py-2.5 text-xs">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-primary whitespace-nowrap">{f.source}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono whitespace-nowrap">{f.destination}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0 ml-3">
                  <span className="rounded bg-accent px-1.5 py-0.5 text-[10px] font-medium">{f.protocol}</span>
                  <span className="text-muted-foreground font-mono">:{f.port}</span>
                  <span className="text-muted-foreground">{(f.bytes / 1048576).toFixed(1)}MB</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top ports */}
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
            <Network size={16} className="text-primary" />
            Top port sử dụng
          </h3>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={topPorts} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222 30% 16%)" />
              <XAxis type="number" stroke="hsl(215 20% 55%)" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="hsl(215 20% 55%)" tick={{ fontSize: 11 }} width={100} />
              <Tooltip contentStyle={{ backgroundColor: 'hsl(222 44% 8%)', border: '1px solid hsl(222 30% 16%)', borderRadius: '8px', color: 'hsl(210 40% 92%)' }} />
              <Bar dataKey="packets" fill="hsl(210 100% 52%)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Anomalies */}
      <div className="rounded-lg border border-border bg-card p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
          <AlertTriangle size={16} className="text-warning" />
          Phát hiện bất thường
        </h3>
        <div className="space-y-3">
          {anomalies.map(a => (
            <div key={a.id} className={`rounded-md border p-4 ${a.severity === 'Critical' ? 'border-critical/30 bg-critical/5' : 'border-warning/30 bg-warning/5'}`}>
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">{a.description}</p>
                  <p className="mt-1 text-xs text-muted-foreground font-mono">
                    {a.source} → {a.destination}
                  </p>
                </div>
                <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${a.severity === 'Critical' ? 'border-critical/30 bg-critical/15 text-critical' : 'border-medium/30 bg-medium/15 text-medium'}`}>
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
