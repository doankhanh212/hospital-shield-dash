import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, Filter, Monitor, RefreshCw, ChevronLeft, ChevronRight, Plus,
  Pencil, Trash2, X, Loader2, AlertCircle, ArrowDownAZ, ShieldAlert,
  HeartPulse, ArrowUp, ArrowDown, FileDown,
} from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import EmptyState from '@/components/widgets/EmptyState';
import { TableSkeleton } from '@/components/widgets/Skeletons';
import { useAssets, useCreateAsset, useUpdateAsset, useDeleteAsset } from '@/hooks/useApi';
import { AssetRow, api } from '@/lib/api';
import { format } from 'date-fns';

// ─── Confidence cap ─────────────────────────────────────────────────────────
// This is an INFERENCE system — never imply certainty.
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

const deviceTypes = [
  'Tat ca', 'IoMT', 'IoT', 'Network', 'Workstation', 'Server',
  'Printer', 'IP Camera', 'Unknown',
];

const CONFIDENCE_RANGES: { label: string; min: number; max: number }[] = [
  { label: 'Tin cay: Tat ca',        min: 0,  max: 100 },
  { label: 'Cao (>= 90)',            min: 90, max: 100 },
  { label: 'Trung binh (60-89)',     min: 60, max: 89 },
  { label: 'Thap (30-59)',           min: 30, max: 59 },
  { label: 'Rat thap (< 30)',        min: 0,  max: 29 },
];

type SortKey = 'confidence_desc' | 'confidence_asc' | 'ip' | 'device_type';
const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: 'confidence_desc', label: 'Tin cay (est.) \u2193' },
  { value: 'confidence_asc',  label: 'Tin cay (est.) \u2191' },
  { value: 'ip',              label: 'IP' },
  { value: 'device_type',     label: 'Loai thiet bi' },
];

const PAGE_SIZE = 20;

const getConfidence = (a: AssetRow): number =>
  capConf(Number(a.confidence ?? a.confidence_score ?? 0));

const confLabel = (c: number): { text: string; cls: string } => {
  if (c >= 90) return { text: 'Cao',        cls: 'text-emerald-400' };
  if (c >= 60) return { text: 'Trung binh', cls: 'text-blue-400' };
  if (c >= 30) return { text: 'Thap',       cls: 'text-amber-400' };
  return                { text: 'Rat thap',  cls: 'text-rose-400' };
};

const confBarColor = (c: number): string => {
  if (c >= 90) return 'bg-emerald-500';
  if (c >= 60) return 'bg-blue-500';
  if (c >= 30) return 'bg-amber-500';
  return 'bg-rose-500';
};

type CvssSeverity = 'critical' | 'high' | 'medium' | 'low';

const severityFromCvss = (score: number): CvssSeverity => {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
};

const SEVERITY_STYLE: Record<CvssSeverity, string> = {
  critical: 'border-rose-500/40    bg-rose-500/15    text-rose-300',
  high:     'border-orange-500/40  bg-orange-500/15  text-orange-300',
  medium:   'border-amber-500/40   bg-amber-500/15   text-amber-300',
  low:      'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
};

const SEVERITY_LABEL: Record<CvssSeverity, string> = {
  critical: 'Critical',
  high:     'High',
  medium:   'Medium',
  low:      'Low',
};

function CvssBadge({ score }: { score: number }) {
  if (!score || score <= 0) {
    return <span className="text-[10px] text-muted-foreground">—</span>;
  }
  const sev = severityFromCvss(score);
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-semibold ${SEVERITY_STYLE[sev]}`}
      title={`CVSS ${score.toFixed(1)} — ${SEVERITY_LABEL[sev]}`}
    >
      <span className="font-mono">{score.toFixed(1)}</span>
      <span className="font-normal opacity-80">({SEVERITY_LABEL[sev]})</span>
    </span>
  );
}

// ─── Component ──────────────────────────────────────────────────────────────

const AssetsPage = () => {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [deviceTypeFilter, setDeviceTypeFilter] = useState('Tat ca');
  const [statusFilter, setStatusFilter] = useState('Tat ca');
  const [vendorFilter, setVendorFilter] = useState('Tat ca');
  const [debouncedVendor, setDebouncedVendor] = useState('Tat ca');
  const [confidenceRangeIdx, setConfidenceRangeIdx] = useState(0);
  const [sortKey, setSortKey] = useState<SortKey>('confidence_desc');

  // Debounce text inputs — 400ms
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedSearch(search); setPage(1); }, 400);
    return () => clearTimeout(t);
  }, [search]);
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedVendor(vendorFilter); setPage(1); }, 400);
    return () => clearTimeout(t);
  }, [vendorFilter]);

  // CRUD modal state
  const [showCreate, setShowCreate] = useState(false);
  const [editAsset, setEditAsset] = useState<AssetRow | null>(null);
  const [deleteAsset, setDeleteAsset] = useState<AssetRow | null>(null);
  const [showReport, setShowReport] = useState(false);

  const offset = (page - 1) * PAGE_SIZE;
  const confRange = CONFIDENCE_RANGES[confidenceRangeIdx];

  // Build server-side filter params
  const apiParams = {
    limit: PAGE_SIZE,
    offset,
    sort: sortKey,
    ...(debouncedSearch ? { search: debouncedSearch } : {}),
    ...(deviceTypeFilter !== 'Tat ca' ? { device_type: deviceTypeFilter } : {}),
    ...(statusFilter !== 'Tat ca' ? { status: statusFilter } : {}),
    ...(debouncedVendor !== 'Tat ca' ? { vendor: debouncedVendor } : {}),
    ...(confidenceRangeIdx !== 0 ? { min_confidence: confRange.min, max_confidence: confRange.max } : {}),
  };

  const { data, isLoading, isError, error, refetch } = useAssets(apiParams);
  const createAsset = useCreateAsset();
  const updateAsset = useUpdateAsset();
  const deleteAssetMut = useDeleteAsset();

  const assets = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const handleFilterChange = <T,>(setter: (v: T) => void) => (v: T) => {
    setter(v);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch('');
    setDeviceTypeFilter('Tat ca');
    setStatusFilter('Tat ca');
    setVendorFilter('Tat ca');
    setConfidenceRangeIdx(0);
    setPage(1);
  };

  const getPageNumbers = (): (number | '...')[] => {
    const pages: (number | '...')[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (page > 3) pages.push('...');
      const start = Math.max(2, page - 1);
      const end = Math.min(totalPages - 1, page + 1);
      for (let i = start; i <= end; i++) pages.push(i);
      if (page < totalPages - 2) pages.push('...');
      pages.push(totalPages);
    }
    return pages;
  };

  return (
    <div className="space-y-6">
      {/* CRUD modals */}
      {showCreate && (
        <AssetFormModal
          title="Them thiet bi"
          onClose={() => setShowCreate(false)}
          onSubmit={vals => createAsset.mutate(vals, { onSuccess: () => setShowCreate(false) })}
          loading={createAsset.isPending}
          error={createAsset.error instanceof Error ? createAsset.error.message : null}
        />
      )}
      {editAsset && (
        <AssetFormModal
          title="Chinh sua thiet bi"
          initial={editAsset}
          onClose={() => setEditAsset(null)}
          onSubmit={vals => updateAsset.mutate({ id: editAsset.id, body: vals }, { onSuccess: () => setEditAsset(null) })}
          loading={updateAsset.isPending}
          error={updateAsset.error instanceof Error ? updateAsset.error.message : null}
        />
      )}
      {deleteAsset && (
        <DeleteConfirmModal
          asset={deleteAsset}
          onClose={() => setDeleteAsset(null)}
          onConfirm={() => deleteAssetMut.mutate(deleteAsset.id, { onSuccess: () => setDeleteAsset(null) })}
          loading={deleteAssetMut.isPending}
        />
      )}
      {showReport && <ReportModal onClose={() => setShowReport(false)} />}

      <PageHeader
        title="Quan ly tai san"
        description={`${total} thiet bi phat hien tu Zeek — Du lieu phan loai la ket qua suy luan, khong phai su that tuyet doi`}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowReport(true)}
              className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
              title="Chon dai mang va xuat bao cao CVSS"
            >
              <FileDown size={13} /> Xuat bao cao
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
            >
              <Plus size={13} /> Them thiet bi
            </button>
            <button onClick={() => refetch()} className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <RefreshCw size={13} /> Lam moi
            </button>
          </div>
        }
      />

      {isError && (
        <div className="flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <AlertCircle size={16} />
          <span>Loi tai tai san: {error instanceof Error ? error.message : 'Unknown error'}</span>
        </div>
      )}

      {/* Filters — two rows for more space */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={15} />
            <input
              className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
              placeholder="Tim theo IP, MAC, Vendor, Hostname..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <div className="flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground">
            <ArrowDownAZ size={13} className="text-muted-foreground" />
            <select
              className="bg-transparent text-xs text-foreground focus:outline-none"
              value={sortKey}
              onChange={e => { setSortKey(e.target.value as SortKey); setPage(1); }}
            >
              {SORT_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Filter size={14} className="text-muted-foreground" />
          <select
            className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none transition-colors"
            value={deviceTypeFilter}
            onChange={e => handleFilterChange(setDeviceTypeFilter)(e.target.value)}
          >
            {deviceTypes.map(d => <option key={d} value={d}>{d === 'Tat ca' ? 'Loai thiet bi: Tat ca' : d}</option>)}
          </select>
          <select
            className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none transition-colors"
            value={statusFilter}
            onChange={e => handleFilterChange(setStatusFilter)(e.target.value)}
          >
            {['Tat ca', 'online', 'offline'].map(s => <option key={s} value={s}>{s === 'Tat ca' ? 'Trang thai: Tat ca' : s}</option>)}
          </select>
          <input
            className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors w-32"
            placeholder="Vendor..."
            value={vendorFilter === 'Tat ca' ? '' : vendorFilter}
            onChange={e => handleFilterChange(setVendorFilter)(e.target.value || 'Tat ca')}
          />
          <select
            className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none transition-colors"
            value={confidenceRangeIdx}
            onChange={e => handleFilterChange(setConfidenceRangeIdx)(Number(e.target.value))}
            title="Loc theo muc do tin cay"
          >
            {CONFIDENCE_RANGES.map((r, i) => (
              <option key={r.label} value={i}>{r.label}</option>
            ))}
          </select>
        </div>
      </div>

      {isLoading ? (
        <TableSkeleton rows={8} cols={10} />
      ) : assets.length === 0 ? (
        <EmptyState
          icon={Monitor}
          title="Khong tim thay thiet bi"
          description="Thu thay doi bo loc hoac tu khoa tim kiem."
          action={
            <button onClick={clearFilters} className="rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors">
              Xoa bo loc
            </button>
          }
        />
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-3">Trang thai</th>
                  <SortableTh label="IP" active={sortKey === 'ip'} onClick={() => { setSortKey('ip'); setPage(1); }} />
                  <SortableTh label="Loai thiet bi" active={sortKey === 'device_type'} onClick={() => { setSortKey('device_type'); setPage(1); }} />
                  <th className="px-3 py-3">Vendor</th>
                  <SortableTh
                    label="Tin cay (est.)"
                    active={sortKey === 'confidence_desc' || sortKey === 'confidence_asc'}
                    direction={sortKey === 'confidence_asc' ? 'asc' : 'desc'}
                    onClick={() => {
                      setSortKey(prev => prev === 'confidence_desc' ? 'confidence_asc' : 'confidence_desc');
                      setPage(1);
                    }}
                  />
                  <th className="px-3 py-3">CVE</th>
                  <th className="px-3 py-3">CVSS</th>
                  <th className="px-3 py-3">Ket noi</th>
                  <th className="px-3 py-3">Hoat dong cuoi</th>
                  <th className="px-3 py-3 w-16"></th>
                </tr>
              </thead>
              <tbody>
                {assets.map(asset => {
                  const conf = getConfidence(asset);
                  const dt = asset.deviceType ?? 'Unknown';
                  const isUnknown = dt === 'Unknown';
                  const isIoMT    = dt === 'IoMT';
                  const cl = confLabel(conf);
                  const vulnCount = asset.vuln_count ?? 0;
                  const maxCvss = asset.max_cvss ?? 0;

                  const rowTint =
                    vulnCount > 0 && maxCvss >= 9 ? 'bg-rose-500/[0.06] hover:bg-rose-500/10'
                    : vulnCount > 0 && maxCvss >= 7 ? 'bg-orange-500/[0.05] hover:bg-orange-500/10'
                    : vulnCount > 0 ? 'bg-amber-500/[0.04] hover:bg-amber-500/10'
                    : 'hover:bg-accent/40';

                  return (
                  <tr
                    key={asset.id}
                    className={`border-b border-border/30 cursor-pointer transition-colors ${rowTint}`}
                    onClick={() => navigate(`/assets/${asset.id}`)}
                  >
                    {/* Status */}
                    <td className="px-3 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                        asset.status === 'online'
                          ? 'bg-success/15 text-success border border-success/25'
                          : 'bg-muted text-muted-foreground'
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${asset.status === 'online' ? 'bg-success' : 'bg-muted-foreground'}`} />
                        {asset.status === 'online' ? 'Online' : 'Offline'}
                      </span>
                    </td>

                    {/* IP + MAC */}
                    <td className="px-3 py-3">
                      <span className="font-mono text-xs text-primary font-medium block">{asset.ip || '\u2014'}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">{asset.mac?.startsWith('ip:') ? '' : (asset.mac || '')}</span>
                    </td>

                    {/* Device Type */}
                    <td className="px-3 py-3">
                      <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold ${DEVICE_TYPE_COLORS[dt] ?? DEVICE_TYPE_COLORS.Unknown}`}>
                        {isIoMT   && <HeartPulse  size={11} className="shrink-0" />}
                        {isUnknown && <ShieldAlert size={11} className="shrink-0" />}
                        {dt}
                      </span>
                    </td>

                    {/* Vendor */}
                    <td className="px-3 py-3 text-xs">{asset.vendor || 'Unknown'}</td>

                    {/* Confidence (estimated) */}
                    <td className="px-3 py-3">
                      <div
                        className="flex items-center gap-1.5"
                        title={`Do tin cay uoc tinh dua tren hanh vi mang. Toi da ${CONFIDENCE_CAP}%.`}
                      >
                        <div className="h-1.5 w-10 rounded-full bg-muted overflow-hidden">
                          <div
                            className={`h-full rounded-full ${confBarColor(conf)}`}
                            style={{ width: `${conf}%` }}
                          />
                        </div>
                        <span className={`text-[11px] font-mono font-semibold ${cl.cls}`}>
                          {conf}%
                        </span>
                      </div>
                    </td>

                    {/* CVE */}
                    <td className="px-3 py-3">
                      {vulnCount > 0 ? (
                        <div
                          className="inline-flex items-center gap-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[11px] font-semibold text-rose-300"
                          title={`${vulnCount} CVE`}
                        >
                          <ShieldAlert size={11} />
                          <span className="font-mono">{vulnCount}</span>
                        </div>
                      ) : (
                        <span className="text-[10px] text-muted-foreground">Khong co</span>
                      )}
                    </td>

                    {/* CVSS (Severity) */}
                    <td className="px-3 py-3">
                      <CvssBadge score={maxCvss} />
                    </td>

                    {/* Connections */}
                    <td className="px-3 py-3 font-mono text-xs">{Number(asset.connection_count).toLocaleString()}</td>

                    {/* Last seen */}
                    <td className="px-3 py-3 text-[11px] text-muted-foreground">
                      {asset.last_seen ? format(new Date(asset.last_seen), 'dd/MM HH:mm') : '\u2014'}
                    </td>

                    {/* Actions */}
                    <td className="px-3 py-3" onClick={e => e.stopPropagation()}>
                      <div className="flex gap-1">
                        <button
                          onClick={() => setEditAsset(asset)}
                          className="flex items-center justify-center rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                          title="Chinh sua"
                        >
                          <Pencil size={13} />
                        </button>
                        <button
                          onClick={() => setDeleteAsset(asset)}
                          className="flex items-center justify-center rounded p-1.5 text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors"
                          title="Xoa"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination footer */}
          <div className="flex items-center justify-between border-t border-border px-4 py-3 text-[12px] text-muted-foreground">
            <span>
              Hien thi {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} / {total} thiet bi
            </span>

            <div className="flex items-center gap-1">
              <button
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <ChevronLeft size={14} />
              </button>

              {getPageNumbers().map((p, i) =>
                p === '...' ? (
                  <span key={`dots-${i}`} className="px-1.5 text-muted-foreground select-none">…</span>
                ) : (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`flex h-8 min-w-[32px] items-center justify-center rounded-lg px-2 text-xs font-medium transition-colors ${
                      page === p
                        ? 'bg-primary text-primary-foreground shadow-sm'
                        : 'border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent'
                    }`}
                  >
                    {p}
                  </button>
                ),
              )}

              <button
                disabled={page >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <ChevronRight size={14} />
              </button>
            </div>

            <button
              onClick={clearFilters}
              className="text-[11px] hover:text-foreground transition-colors"
            >
              Xoa bo loc
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Sortable table header ───────────────────────────────────────────────────

function SortableTh({ label, active, direction, onClick }: {
  label: string;
  active: boolean;
  direction?: 'asc' | 'desc';
  onClick: () => void;
}) {
  return (
    <th
      className="px-3 py-3 cursor-pointer select-none hover:text-foreground transition-colors"
      onClick={onClick}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active ? (
          direction === 'asc'
            ? <ArrowUp size={11} className="text-primary" />
            : <ArrowDown size={11} className="text-primary" />
        ) : null}
      </span>
    </th>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

interface AssetFormValues {
  mac_address: string;
  ip_address: string;
  vendor: string;
  hostname: string;
}

interface AssetFormModalProps {
  title: string;
  initial?: AssetRow;
  onClose: () => void;
  onSubmit: (vals: AssetFormValues) => void;
  loading: boolean;
  error: string | null;
}

function AssetFormModal({ title, initial, onClose, onSubmit, loading, error }: AssetFormModalProps) {
  const [mac, setMac] = useState(initial?.mac ?? '');
  const [ip, setIp] = useState(initial?.ip ?? '');
  const [vendor, setVendor] = useState(initial?.vendor ?? '');
  const [hostname, setHostname] = useState(initial?.hostname ?? '');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ mac_address: mac, ip_address: ip, vendor, hostname });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors">
            <X size={16} />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4 p-5">
          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2.5 text-xs text-destructive">
              <AlertCircle size={14} />
              {error}
            </div>
          )}
          <div>
            <label className="mb-1.5 block text-xs font-medium text-foreground">MAC Address <span className="text-destructive">*</span></label>
            <input
              required
              value={mac}
              onChange={e => setMac(e.target.value)}
              placeholder="aa:bb:cc:dd:ee:ff"
              className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm font-mono text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-foreground">Dia chi IP</label>
            <input
              value={ip}
              onChange={e => setIp(e.target.value)}
              placeholder="192.168.1.100"
              className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm font-mono text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-foreground">Vendor</label>
            <input
              value={vendor}
              onChange={e => setVendor(e.target.value)}
              placeholder="Cisco, Dell, ..."
              className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-foreground">Hostname</label>
            <input
              value={hostname}
              onChange={e => setHostname(e.target.value)}
              placeholder="pc-reception.hospital.local"
              className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors"
            >
              Huy
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60 transition-colors"
            >
              {loading && <Loader2 size={13} className="animate-spin" />}
              {initial ? 'Luu thay doi' : 'Them thiet bi'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

interface DeleteConfirmModalProps {
  asset: AssetRow;
  onClose: () => void;
  onConfirm: () => void;
  loading: boolean;
}

function DeleteConfirmModal({ asset, onClose, onConfirm, loading }: DeleteConfirmModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-sm rounded-xl border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">Xoa thiet bi</h2>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors">
            <X size={16} />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-3">
            <AlertCircle size={16} className="mt-0.5 shrink-0 text-destructive" />
            <div className="text-xs text-foreground">
              <p className="font-medium text-destructive mb-1">Xac nhan xoa thiet bi</p>
              <p className="text-muted-foreground">
                Thiet bi <span className="font-mono font-medium text-foreground">{asset.ip || asset.mac}</span> se bi xoa vinh vien.
                Hanh dong nay khong the hoan tac.
              </p>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              onClick={onClose}
              className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors"
            >
              Huy
            </button>
            <button
              onClick={onConfirm}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg bg-destructive px-4 py-2 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-60 transition-colors"
            >
              {loading && <Loader2 size={13} className="animate-spin" />}
              Xoa thiet bi
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Report modal ────────────────────────────────────────────────────────────

function ReportModal({ onClose }: { onClose: () => void }) {
  const [subnets, setSubnets] = useState<{ cidr: string; node_count: number }[] | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loadingList, setLoadingList] = useState(true);
  const [busy, setBusy] = useState<null | 'view' | 'download'>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.reportSubnets()
      .then(r => {
        if (!alive) return;
        setSubnets(r.subnets);
        // Default: select every subnet that has at least one asset
        setSelected(new Set(r.subnets.filter(s => s.node_count > 0).map(s => s.cidr)));
      })
      .catch(e => { if (alive) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (alive) setLoadingList(false); });
    return () => { alive = false; };
  }, []);

  const toggle = (cidr: string) => {
    setSelected(prev => {
      const n = new Set(prev);
      if (n.has(cidr)) n.delete(cidr); else n.add(cidr);
      return n;
    });
  };

  const selectAll = () => {
    if (!subnets) return;
    setSelected(new Set(subnets.map(s => s.cidr)));
  };
  const clearAll = () => setSelected(new Set());

  const totalNodes = (subnets ?? [])
    .filter(s => selected.has(s.cidr))
    .reduce((acc, s) => acc + s.node_count, 0);

  const run = async (mode: 'view' | 'download') => {
    if (selected.size === 0) {
      setError('Phai chon it nhat mot dai mang');
      return;
    }
    setError(null);
    setBusy(mode);
    try {
      const { blobUrl, filename } = await api.reportHtml({
        download: mode === 'download',
        subnets: Array.from(selected),
      });
      if (mode === 'view') {
        window.open(blobUrl, '_blank', 'noopener');
      } else {
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60_000);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Loi khong xac dinh');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">Xuat bao cao CVSS</h2>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors">
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <p className="text-xs text-muted-foreground">
            Chon cac dai mang (CIDR) can dua vao bao cao. Bao cao se liet ke day du thiet bi va CVE
            trong pham vi duoc chon.
          </p>

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
              <span className="break-all">{error}</span>
            </div>
          )}

          {loadingList ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-6 justify-center">
              <Loader2 size={14} className="animate-spin" /> Dang tai danh sach dai mang...
            </div>
          ) : subnets && subnets.length === 0 ? (
            <div className="rounded-lg border border-border bg-muted/20 px-3 py-4 text-center text-xs text-muted-foreground">
              Chua cau hinh LOCAL_SUBNETS tren backend.
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                <span>{selected.size} / {subnets?.length ?? 0} dai mang — uoc tinh {totalNodes} thiet bi</span>
                <div className="flex gap-2">
                  <button onClick={selectAll} className="hover:text-foreground transition-colors">Chon tat ca</button>
                  <span>·</span>
                  <button onClick={clearAll} className="hover:text-foreground transition-colors">Bo chon</button>
                </div>
              </div>

              <div className="max-h-[280px] space-y-1 overflow-y-auto rounded-lg border border-border bg-background/40 p-2">
                {(subnets ?? []).map(s => {
                  const checked = selected.has(s.cidr);
                  return (
                    <label
                      key={s.cidr}
                      className={`flex cursor-pointer items-center justify-between gap-3 rounded-md border px-3 py-2 text-xs transition-colors ${
                        checked
                          ? 'border-primary/40 bg-primary/5'
                          : 'border-transparent hover:bg-accent/40'
                      }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggle(s.cidr)}
                          className="h-3.5 w-3.5 accent-primary"
                        />
                        <span className="font-mono text-foreground truncate">{s.cidr}</span>
                      </div>
                      <span className="text-[11px] text-muted-foreground shrink-0">
                        {s.node_count} thiet bi
                      </span>
                    </label>
                  );
                })}
              </div>
            </>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-lg border border-border px-4 py-2 text-xs font-medium text-foreground hover:bg-accent transition-colors"
          >
            Huy
          </button>
          <button
            onClick={() => run('view')}
            disabled={busy !== null || selected.size === 0}
            className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-xs font-medium text-foreground hover:bg-accent disabled:opacity-60 transition-colors"
          >
            {busy === 'view' ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
            Xem truoc
          </button>
          <button
            onClick={() => run('download')}
            disabled={busy !== null || selected.size === 0}
            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60 transition-colors"
          >
            {busy === 'download' ? <Loader2 size={13} className="animate-spin" /> : <FileDown size={13} />}
            Tai ve
          </button>
        </div>
      </div>
    </div>
  );
}

export default AssetsPage;
