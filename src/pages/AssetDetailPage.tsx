import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Globe, Activity, Clock,
  ShieldAlert, HeartPulse,
  AlertTriangle, Network, Lock, Cog, Brain,
  CircuitBoard, HelpCircle, Monitor, Bug,
} from 'lucide-react';
import { useAsset } from '@/hooks/useApi';
import AssetAnomalyPanel from '@/components/xdr/AssetAnomalyPanel';
import { format } from 'date-fns';

// ─── Confidence cap — inference system, never 100% ──────────────────────────
const CONFIDENCE_CAP = 95;
const capConf = (raw: number) => Math.min(raw, CONFIDENCE_CAP);

const DEVICE_TYPE_COLORS: Record<string, string> = {
  IoMT:        'bg-violet-500/20 text-violet-300 border border-violet-500/40',
  IoT:         'bg-amber-500/15 text-amber-400 border border-amber-500/25',
  Network:     'bg-blue-500/15 text-blue-400 border border-blue-500/25',
  Workstation: 'bg-sky-500/15 text-sky-300 border border-sky-500/25',
  Server:      'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25',
  Scanner:     'bg-orange-500/15 text-orange-400 border border-orange-500/25',
  Printer:     'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25',
  'IP Camera': 'bg-pink-500/15 text-pink-400 border border-pink-500/25',
  Unknown:     'bg-rose-500/15 text-rose-300 border border-rose-500/30',
};

const BEHAVIOR_ICONS: Record<string, React.ElementType> = {
  'User Browsing':      Globe,
  'Automation / Script': Cog,
  'Backend Service':    Brain,
  'Windows Service':    Brain,
  'Generic Client':     Monitor,
  'Embedded Device':    CircuitBoard,
  'Medical Device':     HeartPulse,
  'Unknown':            HelpCircle,
};

const BEHAVIOR_COLORS: Record<string, string> = {
  'User Browsing':      'text-blue-400 border-blue-500/30 bg-blue-500/10',
  'Automation / Script': 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  'Backend Service':    'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
  'Windows Service':    'text-sky-400 border-sky-500/30 bg-sky-500/10',
  'Generic Client':     'text-slate-400 border-slate-500/30 bg-slate-500/10',
  'Embedded Device':    'text-amber-400 border-amber-500/30 bg-amber-500/10',
  'Medical Device':     'text-violet-400 border-violet-500/30 bg-violet-500/10',
  'Unknown':            'text-muted-foreground border-border bg-muted/20',
};

const confScoreColor = (c: number): string => {
  if (c >= 90) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5';
  if (c >= 60) return 'text-blue-400 border-blue-500/30 bg-blue-500/5';
  if (c >= 30) return 'text-amber-400 border-amber-500/30 bg-amber-500/5';
  return 'text-rose-400 border-rose-500/30 bg-rose-500/5';
};

const AssetDetailPage = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: asset, isLoading, isError } = useAsset(id ?? '');

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <p className="text-muted-foreground text-sm">Dang tai...</p>
      </div>
    );
  }

  if (isError || !asset) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <p className="text-muted-foreground">Khong tim thay thiet bi</p>
      </div>
    );
  }

  const Section = ({ title, icon: Icon, children, className: cls }: { title: string; icon: React.ElementType; children: React.ReactNode; className?: string }) => (
    <div className={`rounded-lg border border-border bg-card p-5 ${cls ?? ''}`}>
      <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
        <Icon size={16} className="text-primary" />
        {title}
      </h3>
      {children}
    </div>
  );

  const InfoRow = ({ label, value, mono }: { label: string; value?: string | null; mono?: boolean }) => (
    <div className="flex justify-between border-b border-border/50 py-2 last:border-0">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={`max-w-[65%] break-all text-right text-xs text-foreground ${mono !== false ? 'font-mono' : ''}`}>{value || '\u2014'}</span>
    </div>
  );

  const displayMac = asset.mac_address?.startsWith('ip:') ? null : asset.mac_address;
  const primaryIp = asset.ips?.[0]?.ip ?? null;
  const conf = capConf(Number(asset.confidence_score ?? 0));

  const inference = asset.inference;
  const vulnerabilities = asset.vulnerabilities ?? [];
  const maxCvss = vulnerabilities.reduce((m, v) => Math.max(m, v.cvss_score ?? 0), 0);
  const fingerprints = asset.fingerprints ?? [];
  const pickFingerprintValue = (key: 'ja3' | 'ja3s' | 'user_agent' | 'dhcp_vendor') =>
    fingerprints.find((row) => row?.[key])?.[key] ?? null;
  const fingerprintSummary = {
    ja3: pickFingerprintValue('ja3'),
    ja3s: pickFingerprintValue('ja3s'),
    user_agent: pickFingerprintValue('user_agent'),
    dhcp_vendor: pickFingerprintValue('dhcp_vendor'),
  };

  const dt = inference?.device_type ?? (asset as { deviceType?: string }).deviceType ?? 'Unknown';
  const bt = inference?.behavior_type ?? asset.behavior_type ?? 'Unknown';
  const isIoMT    = dt === 'IoMT';
  const isUnknown = dt === 'Unknown';
  const isLowConf = conf < 30;

  const BehaviorIcon = BEHAVIOR_ICONS[bt] ?? HelpCircle;
  const behaviorStyle = BEHAVIOR_COLORS[bt] ?? BEHAVIOR_COLORS.Unknown;

  const tlsSniList = asset.tls_server_names ?? [];

  return (
    <div className="space-y-6">
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
        <ArrowLeft size={16} /> Quay lai
      </button>

      {/* ── Risk banners ──────────────────────────────────────────────── */}
      {isUnknown && (
        <div className="flex items-center gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          <ShieldAlert size={18} className="shrink-0" />
          <div>
            <p className="font-semibold">Thiet bi chua duoc phan loai</p>
            <p className="text-xs text-rose-300/70">Can xac minh thu cong — thiet bi khong xac dinh tren mang benh vien la moi rui ro tiem tang.</p>
          </div>
        </div>
      )}
      {isIoMT && (
        <div className="flex items-center gap-3 rounded-lg border border-violet-500/30 bg-violet-500/10 px-4 py-3 text-sm text-violet-300">
          <HeartPulse size={18} className="shrink-0" />
          <div>
            <p className="font-semibold">Thiet bi y te (IoMT)</p>
            <p className="text-xs text-violet-300/70">Thiet bi y te duoc ket noi — can tuan thu chinh sach bao mat dac biet va giam sat tang cuong.</p>
          </div>
        </div>
      )}
      {isLowConf && !isUnknown && (
        <div className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          <AlertTriangle size={18} className="shrink-0" />
          <div>
            <p className="font-semibold">Do tin cay rat thap ({conf}%)</p>
            <p className="text-xs text-amber-300/70">Ket qua phan loai co do tin cay thap — can kiem tra bang chung va xac nhan thu cong.</p>
          </div>
        </div>
      )}

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-foreground">{primaryIp ?? asset.mac_address}</h2>
          <p className="text-sm text-muted-foreground">{asset.vendor ?? 'Unknown Vendor'}</p>
        </div>
        <div className="flex items-center gap-3">
          {/* Device type badge */}
          <span className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${DEVICE_TYPE_COLORS[dt] ?? DEVICE_TYPE_COLORS.Unknown}`}>
            {isIoMT   && <HeartPulse  size={13} />}
            {isUnknown && <ShieldAlert size={13} />}
            {dt}
          </span>
          {/* Behavior badge */}
          <span className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold ${behaviorStyle}`}>
            <BehaviorIcon size={13} />
            {bt}
          </span>
          {/* Confidence score */}
          <div className={`flex items-center gap-2 rounded-lg border px-4 py-2 ${confScoreColor(conf)}`} title={`Do tin cay uoc tinh dua tren hanh vi mang. Toi da ${CONFIDENCE_CAP}%.`}>
            <span className="text-xs font-medium">Tin cay (est.)</span>
            <span className="text-lg font-bold font-mono">{conf}%</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* ── Identity (Basic info) ──────────────────────────────────── */}
        <Section title="Thong tin co ban" icon={Globe}>
          <InfoRow label="IP chinh" value={primaryIp} />
          <InfoRow label="Dia chi MAC" value={displayMac} />
          <InfoRow label="Vendor" value={asset.vendor} />
          <InfoRow label="Hostname" value={asset.hostnames?.[0]?.hostname} />
          <InfoRow label="Trang thai" value={asset.asset_status} mono={false} />
          <InfoRow label="Lan dau phat hien" value={asset.first_seen ? format(new Date(asset.first_seen), 'dd/MM/yyyy HH:mm') : undefined} />
          <InfoRow label="Hoat dong cuoi" value={asset.last_seen ? format(new Date(asset.last_seen), 'dd/MM/yyyy HH:mm') : undefined} />
          {asset.hostnames && asset.hostnames.length > 1 && (
            <div className="mt-2 pt-2 border-t border-border/30">
              <p className="text-[11px] text-muted-foreground mb-1.5">Hostname khac ({asset.hostnames.length - 1})</p>
              <div className="flex flex-wrap gap-1">
                {asset.hostnames.slice(1).map((h, i) => (
                  <span key={i} className="rounded bg-muted/30 px-1.5 py-0.5 text-[10px] font-mono text-foreground">{h.hostname}</span>
                ))}
              </div>
            </div>
          )}
        </Section>

        {/* ── Behavior Panel ─────────────────────────────────────────── */}
        <Section title="Hanh vi mang" icon={Activity}>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className={`flex items-center gap-2 rounded-lg border px-4 py-3 ${behaviorStyle}`}>
                <BehaviorIcon size={18} />
                <div>
                  <p className="text-xs font-semibold">{bt}</p>
                  <p className="text-[10px] opacity-70">Hanh vi suy luan tu JA3/TLS</p>
                </div>
              </div>
            </div>

            {/* JA3/JA3S categories — show category labels, not raw hashes */}
            <div className="space-y-1.5">
              <p className="text-[11px] text-muted-foreground uppercase tracking-wider font-medium">Fingerprint categories</p>
              {fingerprintSummary.user_agent && (
                <div className="flex justify-between rounded border border-border/30 bg-muted/20 px-3 py-2 text-[11px]">
                  <span className="text-muted-foreground">User-Agent</span>
                  <span className="text-foreground break-all text-right max-w-[60%]">{fingerprintSummary.user_agent}</span>
                </div>
              )}
              {fingerprintSummary.dhcp_vendor && (
                <div className="flex justify-between rounded border border-border/30 bg-muted/20 px-3 py-2 text-[11px]">
                  <span className="text-muted-foreground">DHCP Vendor</span>
                  <span className="text-foreground">{fingerprintSummary.dhcp_vendor}</span>
                </div>
              )}
              {fingerprintSummary.ja3 && (
                <div className="flex justify-between rounded border border-border/30 bg-muted/20 px-3 py-2 text-[11px]">
                  <span className="text-muted-foreground">JA3 (client TLS)</span>
                  <span className="text-foreground font-mono text-[10px]">{fingerprintSummary.ja3.slice(0, 16)}...</span>
                </div>
              )}
              {fingerprintSummary.ja3s && (
                <div className="flex justify-between rounded border border-border/30 bg-muted/20 px-3 py-2 text-[11px]">
                  <span className="text-muted-foreground">JA3S (server TLS)</span>
                  <span className="text-foreground font-mono text-[10px]">{fingerprintSummary.ja3s.slice(0, 16)}...</span>
                </div>
              )}
              {!fingerprintSummary.user_agent && !fingerprintSummary.dhcp_vendor && !fingerprintSummary.ja3 && !fingerprintSummary.ja3s && (
                <p className="text-xs text-muted-foreground">Khong co du lieu fingerprint</p>
              )}
            </div>
          </div>
        </Section>

        {/* ── Ports & services ────────────────────────────────────────── */}
        <Section title="Hanh vi mang (Ports / Services)" icon={Activity}>
          {asset.behaviors && asset.behaviors.length > 0 ? (
            <div className="space-y-1.5 max-h-[300px] overflow-y-auto">
              {asset.behaviors.map((b, i) => (
                <div key={i} className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 px-3 py-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">{b.protocol}</span>
                    {b.port != null && <span className="font-mono text-muted-foreground">:{b.port}</span>}
                    {b.service && <span className="text-muted-foreground">{b.service}</span>}
                  </div>
                  <span className="font-mono text-muted-foreground">{b.frequency.toLocaleString()}x</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">Khong co du lieu hanh vi</p>
          )}
        </Section>

        {/* ── TLS / SNI ───────────────────────────────────────────────── */}
        <Section title="TLS / SNI" icon={Lock}>
          {tlsSniList.length > 0 ? (
            <div className="space-y-1 max-h-[200px] overflow-y-auto">
              {tlsSniList.map((sni, i) => (
                <div key={i} className="flex items-center gap-2 rounded border border-border/30 bg-muted/20 px-2.5 py-1.5 text-[11px]">
                  <Network size={12} className="shrink-0 text-primary" />
                  <span className="font-mono text-foreground break-all">{sni}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">Khong co du lieu TLS SNI</p>
          )}
        </Section>

        {/* ── IP history ──────────────────────────────────────────────── */}
        <Section title="Dia chi IP lich su" icon={Clock}>
          {asset.ips && asset.ips.length > 0 ? (
            <div className="space-y-1.5">
              {asset.ips.map((ip, i) => (
                <div key={i} className="flex items-center justify-between border-b border-border/30 py-2 last:border-0">
                  <span className="font-mono text-xs text-primary">{ip.ip}</span>
                  <span className="text-[11px] text-muted-foreground">
                    {ip.last_seen ? format(new Date(ip.last_seen), 'dd/MM/yyyy HH:mm') : '\u2014'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">Khong co du lieu IP</p>
          )}
        </Section>

        {/* ── Vulnerabilities (CVE) ──────────────────────────────────── */}
        <Section title={`Lỗ hổng (${vulnerabilities.length})`} icon={Bug} className="lg:col-span-2">
          {vulnerabilities.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              Chưa phát hiện CVE nào cho thiết bị này. Cần cấu hình NVD API key tại <span className="text-foreground">Tích hợp → Vulnerability Sources</span> và chạy đồng bộ.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    <th className="pb-3 pr-4">CVE ID</th>
                    <th className="pb-3 pr-4">Severity</th>
                    <th className="pb-3 pr-4">CVSS</th>
                    <th className="pb-3 pr-4">Mô tả</th>
                    <th className="pb-3">Phát hiện</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilities.map((v, i) => {
                    const score = v.cvss_score ?? 0;
                    const sev = (v.severity ?? '').toLowerCase();
                    const sevStyle =
                      sev === 'critical' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      : sev === 'high'   ? 'bg-orange-500/20 text-orange-300 border-orange-500/40'
                      : sev === 'medium' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      : sev === 'low'    ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                      : 'bg-muted/30 text-muted-foreground border-border';
                    const scoreColor =
                      score >= 9 ? 'text-rose-400'
                      : score >= 7 ? 'text-orange-400'
                      : score >= 4 ? 'text-amber-400'
                      : 'text-blue-400';
                    return (
                      <tr key={i} className="border-b border-border/30 transition-colors hover:bg-accent/20">
                        <td className="py-2.5 pr-4">
                          <span className="font-mono text-xs text-primary">{v.cve_id ?? '—'}</span>
                        </td>
                        <td className="py-2.5 pr-4">
                          <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${sevStyle}`}>
                            {v.severity ?? '—'}
                          </span>
                        </td>
                        <td className="py-2.5 pr-4">
                          <span className={`font-mono text-xs font-semibold ${scoreColor}`}>
                            {v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'}
                          </span>
                        </td>
                        <td className="py-2.5 pr-4 text-xs text-muted-foreground max-w-md truncate" title={v.description ?? ''}>
                          {v.description ?? '—'}
                        </td>
                        <td className="py-2.5 text-[11px] text-muted-foreground">
                          {v.detected_at ? format(new Date(v.detected_at), 'dd/MM/yyyy') : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        <AssetAnomalyPanel ip={primaryIp} />

      </div>
    </div>
  );
};

export default AssetDetailPage;
