import { useState, useMemo } from 'react';
import { Search, RefreshCw, Network as NetIcon, ShieldAlert } from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { TableSkeleton } from '@/components/widgets/Skeletons';
import { useDns, useTls, useHttp } from '@/hooks/useApi';
import XdrAlertsTab from '@/components/xdr/XdrAlertsTab';
import { format } from 'date-fns';

type LogEntry = {
  id: string;
  timestamp: string;
  type: 'DNS' | 'TLS' | 'HTTP';
  source: string;
  message: string;
};

const typeStyles: Record<string, string> = {
  DNS: 'text-info bg-info/10',
  TLS: 'text-success bg-success/10',
  HTTP: 'text-warning bg-warning/10',
};

function formatTlsMessage(row: {
  server_name: string | null;
  version: string | null;
  next_protocol: string | null;
  validation_status: string | null;
  sni_matches_cert: boolean | null;
  ja3: string | null;
  ja3s: string | null;
  certificate_issuer: string | null;
}) {
  const summary = `${row.server_name ?? '?'} [${row.version ?? '?'}${row.next_protocol ? `/${row.next_protocol}` : ''}]`;
  const details = [
    row.validation_status ? `verify=${row.validation_status}` : null,
    row.sni_matches_cert === null ? null : `sni_cert=${row.sni_matches_cert ? 'match' : 'mismatch'}`,
    row.ja3 ? `ja3=${row.ja3.slice(0, 12)}` : null,
    row.ja3s ? `ja3s=${row.ja3s.slice(0, 12)}` : null,
    row.certificate_issuer,
  ].filter(Boolean);

  return details.length > 0 ? `${summary} — ${details.join(' | ')}` : summary;
}

const LogsPage = () => {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('Tất cả');

  const { data: dnsRows = [], isLoading: loadDns, refetch: refetchDns } = useDns(200);
  const { data: tlsRows = [], isLoading: loadTls, refetch: refetchTls } = useTls(200);
  const { data: httpRows = [], isLoading: loadHttp, refetch: refetchHttp } = useHttp(200);

  const isLoading = loadDns || loadTls || loadHttp;

  const logs: LogEntry[] = useMemo(() => [
    ...dnsRows.map(r => ({
      id: `dns-${r.id}`,
      timestamp: r.timestamp,
      type: 'DNS' as const,
      source: r.src_ip ?? '—',
      message: `${r.query_type ?? 'QUERY'} ${r.query}${r.answer ? ` → ${r.answer}` : ''}`,
    })),
    ...tlsRows.map(r => ({
      id: `tls-${r.id}`,
      timestamp: r.timestamp,
      type: 'TLS' as const,
      source: r.src_ip ?? '—',
      message: formatTlsMessage(r),
    })),
    ...httpRows.map(r => ({
      id: `http-${r.id}`,
      timestamp: r.timestamp,
      type: 'HTTP' as const,
      source: r.src_ip ?? '—',
      message: `${r.method ?? 'GET'} ${r.host ?? '?'}${r.uri ?? ''} ${r.status_code ? `[${r.status_code}]` : ''}`,
    })),
  ].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()), [dnsRows, tlsRows, httpRows]);

  const filtered = logs.filter(l => {
    if (typeFilter !== 'Tất cả' && l.type !== typeFilter) return false;
    if (search && !l.message.toLowerCase().includes(search.toLowerCase()) && !l.source.includes(search)) return false;
    return true;
  });

  const refetchAll = () => { refetchDns(); refetchTls(); refetchHttp(); };

  const [tab, setTab] = useState<'network' | 'alerts'>('network');

  return (
    <div className="space-y-6">
      <PageHeader
        title="Nhật ký hệ thống"
        description={tab === 'network'
          ? `${logs.length} sự kiện từ nhật ký Zeek`
          : 'Cảnh báo bảo mật theo thời gian thực (XDR)'}
        actions={
          <button onClick={refetchAll} className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors">
            <RefreshCw size={13} /> Làm mới
          </button>
        }
      />

      {/* ── Tabs (Network Logs · Security Alerts) ─────────────────────── */}
      <div className="flex border-b border-border">
        <button
          onClick={() => setTab('network')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            tab === 'network'
              ? 'border-b-2 border-primary text-primary'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <NetIcon size={14} /> Nhật ký mạng
        </button>
        <button
          onClick={() => setTab('alerts')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            tab === 'alerts'
              ? 'border-b-2 border-primary text-primary'
              : 'text-muted-foreground hover:text-foreground'
          }`}
        >
          <ShieldAlert size={14} /> Cảnh báo bảo mật
        </button>
      </div>

      {tab === 'alerts' && <XdrAlertsTab />}

      {tab === 'network' && (<>
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={15} />
          <input
            className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
            placeholder="Tìm kiếm nhật ký..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none transition-colors"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
        >
          {['Tất cả', 'DNS', 'TLS', 'HTTP'].map(t => (
            <option key={t} value={t}>{t === 'Tất cả' ? 'Loại: Tất cả' : t}</option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <TableSkeleton rows={10} cols={4} />
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-left text-[10px] font-medium uppercase tracking-wider text-muted-foreground font-sans">
                  <th className="px-4 py-3">Thời gian</th>
                  <th className="px-4 py-3">Loại</th>
                  <th className="px-4 py-3">Nguồn IP</th>
                  <th className="px-4 py-3">Nội dung</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 500).map(log => (
                  <tr key={log.id} className="border-b border-border/30 hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-2.5 text-muted-foreground whitespace-nowrap">
                      {log.timestamp ? format(new Date(log.timestamp), 'dd/MM HH:mm:ss') : '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-bold ${typeStyles[log.type]}`}>
                        {log.type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-foreground">{log.source}</td>
                    <td className="px-4 py-2.5 text-muted-foreground font-sans text-xs truncate max-w-[400px]">{log.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="border-t border-border px-4 py-2.5 text-[11px] text-muted-foreground">
            Hiển thị {Math.min(filtered.length, 500)} / {filtered.length} mục
          </div>
        </div>
      )}
      </>)}
    </div>
  );
};

export default LogsPage;
