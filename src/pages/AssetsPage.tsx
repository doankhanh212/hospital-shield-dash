import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter, Monitor } from 'lucide-react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
import PageHeader from '@/components/widgets/PageHeader';
import EmptyState from '@/components/widgets/EmptyState';
import { TableSkeleton } from '@/components/widgets/Skeletons';
import { assets } from '@/data/mockData';

const deviceTypes = ['Tất cả', 'IoMT', 'IoT', 'Workstation', 'Server', 'Network', 'Chưa xác định'];
const vlans = ['Tất cả', '10', '20', '30', '40', '50'];
const statuses = ['Tất cả', 'online', 'offline', 'unknown'];

const AssetsPage = () => {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('Tất cả');
  const [vlanFilter, setVlanFilter] = useState('Tất cả');
  const [statusFilter, setStatusFilter] = useState('Tất cả');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 600);
    return () => clearTimeout(t);
  }, []);

  const filtered = assets.filter(a => {
    if (search && !a.ip.includes(search) && !a.vendor.toLowerCase().includes(search.toLowerCase()) && !a.mac.toLowerCase().includes(search.toLowerCase())) return false;
    if (typeFilter !== 'Tất cả' && a.deviceType !== typeFilter) return false;
    if (vlanFilter !== 'Tất cả' && a.vlan !== Number(vlanFilter)) return false;
    if (statusFilter !== 'Tất cả' && a.status !== statusFilter) return false;
    return true;
  });

  const SelectFilter = ({ value, onChange, options, prefix }: { value: string; onChange: (v: string) => void; options: string[]; prefix: string }) => (
    <select
      className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
      value={value}
      onChange={e => onChange(e.target.value)}
    >
      {options.map(o => (
        <option key={o} value={o}>
          {o === 'Tất cả' ? `${prefix}: Tất cả` : o === 'online' ? 'Hoạt động' : o === 'offline' ? 'Ngoại tuyến' : o === 'unknown' ? 'Không rõ' : o.startsWith('1') || o.startsWith('2') || o.startsWith('3') || o.startsWith('4') || o.startsWith('5') ? `VLAN ${o}` : o}
        </option>
      ))}
    </select>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quản lý tài sản"
        description={`${assets.length} thiết bị trên mạng bệnh viện`}
      />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={15} />
          <input
            className="w-full rounded-lg border border-border bg-card py-2.5 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary/30 transition-colors"
            placeholder="Tìm theo IP, MAC, Vendor..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter size={14} className="text-muted-foreground" />
          <SelectFilter value={typeFilter} onChange={setTypeFilter} options={deviceTypes} prefix="Loại" />
          <SelectFilter value={vlanFilter} onChange={setVlanFilter} options={vlans} prefix="VLAN" />
          <SelectFilter value={statusFilter} onChange={setStatusFilter} options={statuses} prefix="Trạng thái" />
        </div>
      </div>

      {loading ? (
        <TableSkeleton rows={8} cols={8} />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Monitor}
          title="Không tìm thấy thiết bị"
          description="Thử thay đổi bộ lọc hoặc từ khóa tìm kiếm để hiển thị kết quả."
          action={
            <button onClick={() => { setSearch(''); setTypeFilter('Tất cả'); setVlanFilter('Tất cả'); setStatusFilter('Tất cả'); }} className="rounded-lg bg-primary px-4 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors">
              Xóa bộ lọc
            </button>
          }
        />
      ) : (
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-3">IP</th>
                  <th className="px-4 py-3">MAC</th>
                  <th className="px-4 py-3">Vendor</th>
                  <th className="px-4 py-3">Loại</th>
                  <th className="px-4 py-3">Hệ điều hành</th>
                  <th className="px-4 py-3">Tin cậy</th>
                  <th className="px-4 py-3">Rủi ro</th>
                  <th className="px-4 py-3">Trạng thái</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(asset => (
                  <tr
                    key={asset.id}
                    className="border-b border-border/30 cursor-pointer transition-colors hover:bg-accent/40"
                    onClick={() => navigate(`/assets/${asset.id}`)}
                  >
                    <td className="px-4 py-3 font-mono text-xs text-primary font-medium">{asset.ip}</td>
                    <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground">{asset.mac}</td>
                    <td className="px-4 py-3 text-xs">{asset.vendor}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px] font-medium ${
                        asset.deviceType === 'IoMT' ? 'bg-info/10 text-info' :
                        asset.deviceType === 'IoT' ? 'bg-warning/10 text-warning' :
                        'bg-muted text-muted-foreground'
                      }`}>
                        {asset.deviceType}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[11px] text-muted-foreground">{asset.os}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <div className="h-1.5 w-10 rounded-full bg-muted overflow-hidden">
                          <div className="h-full rounded-full bg-primary" style={{ width: `${asset.confidence}%` }} />
                        </div>
                        <span className="text-[11px] font-mono text-muted-foreground">{asset.confidence}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-bold font-mono ${asset.riskScore >= 80 ? 'text-critical' : asset.riskScore >= 50 ? 'text-warning' : 'text-success'}`}>
                        {asset.riskScore}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 text-[11px] ${asset.status === 'online' ? 'text-success' : asset.status === 'offline' ? 'text-muted-foreground' : 'text-warning'}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${asset.status === 'online' ? 'bg-success' : asset.status === 'offline' ? 'bg-muted-foreground' : 'bg-warning'}`} />
                        {asset.status === 'online' ? 'Online' : asset.status === 'offline' ? 'Offline' : 'N/A'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between border-t border-border px-4 py-2.5 text-[11px] text-muted-foreground">
            <span>Hiển thị {filtered.length} / {assets.length} thiết bị</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default AssetsPage;
