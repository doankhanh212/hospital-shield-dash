import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Globe, Fingerprint, Activity, Bug, Clock } from 'lucide-react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import { assets } from '@/data/mockData';

const AssetDetailPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const asset = assets.find(a => a.id === id);

  if (!asset) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <p className="text-muted-foreground">Không tìm thấy thiết bị</p>
      </div>
    );
  }

  const Section = ({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) => (
    <div className="rounded-lg border border-border bg-card p-5">
      <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
        <Icon size={16} className="text-primary" />
        {title}
      </h3>
      {children}
    </div>
  );

  const InfoRow = ({ label, value }: { label: string; value?: string }) => (
    <div className="flex justify-between border-b border-border/50 py-2 last:border-0">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-xs font-mono text-foreground">{value || '—'}</span>
    </div>
  );

  return (
    <div className="space-y-6">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
        <ArrowLeft size={16} /> Quay lại
      </button>

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-foreground">{asset.ip}</h2>
          <p className="text-sm text-muted-foreground">{asset.vendor} — {asset.deviceType}</p>
        </div>
        <div className={`flex items-center gap-2 rounded-lg border px-4 py-2 ${asset.riskScore >= 80 ? 'border-critical/30 bg-critical/5 text-critical' : asset.riskScore >= 50 ? 'border-warning/30 bg-warning/5 text-warning' : 'border-success/30 bg-success/5 text-success'}`}>
          <span className="text-xs font-medium">Điểm rủi ro</span>
          <span className="text-lg font-bold font-mono">{asset.riskScore}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Section title="Thông tin cơ bản" icon={Globe}>
          <InfoRow label="Địa chỉ IP" value={asset.ip} />
          <InfoRow label="Địa chỉ MAC" value={asset.mac} />
          <InfoRow label="Vendor" value={asset.vendor} />
          <InfoRow label="Loại thiết bị" value={asset.deviceType} />
          <InfoRow label="Hệ điều hành" value={asset.os} />
          <InfoRow label="VLAN" value={String(asset.vlan)} />
          <InfoRow label="Độ tin cậy" value={`${asset.confidence}%`} />
          <InfoRow label="Lần đầu phát hiện" value={asset.firstSeen} />
          <InfoRow label="Hoạt động cuối" value={asset.lastSeen} />
        </Section>

        <Section title="Fingerprint" icon={Fingerprint}>
          <InfoRow label="JA3 Hash" value={asset.ja3} />
          <InfoRow label="User-Agent" value={asset.userAgent} />
          <InfoRow label="DHCP Fingerprint" value={asset.dhcpFingerprint} />
        </Section>

        <Section title="Hành vi mạng" icon={Activity}>
          <div className="space-y-3">
            <div>
              <p className="mb-1.5 text-xs text-muted-foreground">Port sử dụng</p>
              <div className="flex flex-wrap gap-1.5">
                {asset.ports.map(p => (
                  <span key={p} className="rounded bg-primary/10 px-2 py-0.5 text-xs font-mono text-primary">{p}</span>
                ))}
              </div>
            </div>
            <div>
              <p className="mb-1.5 text-xs text-muted-foreground">Giao thức</p>
              <div className="flex flex-wrap gap-1.5">
                {asset.protocols.map(p => (
                  <span key={p} className="rounded bg-accent px-2 py-0.5 text-xs font-medium text-accent-foreground">{p}</span>
                ))}
              </div>
            </div>
          </div>
        </Section>

        <Section title="Lỗ hổng bảo mật" icon={Bug}>
          {asset.vulnerabilities.length === 0 ? (
            <p className="text-xs text-muted-foreground">Không phát hiện lỗ hổng</p>
          ) : (
            <div className="space-y-3">
              {asset.vulnerabilities.map(v => (
                <div key={v.cve} className="rounded-md border border-border/50 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold text-foreground">{v.cve}</span>
                    <SeverityBadge severity={v.severity} />
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{v.description}</p>
                  <div className="mt-2 flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span>CVSS: <strong className="text-foreground">{v.cvss}</strong></span>
                    <span>Công bố: {v.published}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Section>
      </div>

      {/* Timeline */}
      <Section title="Timeline hoạt động" icon={Clock}>
        <div className="space-y-0">
          {asset.activities.map((act, i) => (
            <div key={i} className="flex gap-4 border-l-2 border-border pb-4 pl-4 last:pb-0">
              <div className="relative">
                <span className="absolute -left-[21px] top-0.5 h-2.5 w-2.5 rounded-full border-2 border-primary bg-background" />
              </div>
              <div>
                <p className="text-xs font-mono text-muted-foreground">{act.timestamp}</p>
                <p className="text-sm font-medium text-foreground">{act.action}</p>
                <p className="text-xs text-muted-foreground">{act.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
};

export default AssetDetailPage;
