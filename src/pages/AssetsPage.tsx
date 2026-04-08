import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';
import SeverityBadge from '@/components/widgets/SeverityBadge';
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

  const filtered = assets.filter(a => {
    if (search && !a.ip.includes(search) && !a.vendor.toLowerCase().includes(search.toLowerCase()) && !a.mac.toLowerCase().includes(search.toLowerCase())) return false;
    if (typeFilter !== 'Tất cả' && a.deviceType !== typeFilter) return false;
    if (vlanFilter !== 'Tất cả' && a.vlan !== Number(vlanFilter)) return false;
    if (statusFilter !== 'Tất cả' && a.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-foreground">Quản lý tài sản</h2>
        <p className="text-sm text-muted-foreground">Danh sách tất cả thiết bị trên mạng bệnh viện</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={16} />
          <input
            className="w-full rounded-md border border-border bg-card py-2 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            placeholder="Tìm theo IP, MAC, Vendor..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter size={14} className="text-muted-foreground" />
          <select className="rounded-md border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            {deviceTypes.map(t => <option key={t} value={t}>{t === 'Tất cả' ? 'Loại: Tất cả' : t}</option>)}
          </select>
          <select className="rounded-md border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none" value={vlanFilter} onChange={e => setVlanFilter(e.target.value)}>
            {vlans.map(v => <option key={v} value={v}>{v === 'Tất cả' ? 'VLAN: Tất cả' : `VLAN ${v}`}</option>)}
          </select>
          <select className="rounded-md border border-border bg-card px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
            {statuses.map(s => <option key={s} value={s}>{s === 'Tất cả' ? 'Trạng thái: Tất cả' : s === 'online' ? 'Hoạt động' : s === 'offline' ? 'Ngoại tuyến' : 'Không rõ'}</option>)}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border bg-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
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
                className="border-b border-border/50 cursor-pointer transition-colors hover:bg-accent/50"
                onClick={() => navigate(`/assets/${asset.id}`)}
              >
                <td className="px-4 py-3 font-mono text-xs text-primary">{asset.ip}</td>
                <td className="px-4 py-3 font-mono text-xs">{asset.mac}</td>
                <td className="px-4 py-3">{asset.vendor}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-medium ${asset.deviceType === 'IoMT' ? 'text-info' : asset.deviceType === 'IoT' ? 'text-warning' : ''}`}>
                    {asset.deviceType}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-muted-foreground">{asset.os}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <div className="h-1.5 w-12 rounded-full bg-muted overflow-hidden">
                      <div className="h-full rounded-full bg-primary" style={{ width: `${asset.confidence}%` }} />
                    </div>
                    <span className="text-xs font-mono">{asset.confidence}%</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-bold font-mono ${asset.riskScore >= 80 ? 'text-critical' : asset.riskScore >= 50 ? 'text-warning' : 'text-success'}`}>
                    {asset.riskScore}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center gap-1.5 text-xs ${asset.status === 'online' ? 'text-success' : asset.status === 'offline' ? 'text-muted-foreground' : 'text-warning'}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${asset.status === 'online' ? 'bg-success' : asset.status === 'offline' ? 'bg-muted-foreground' : 'bg-warning'}`} />
                    {asset.status === 'online' ? 'Hoạt động' : asset.status === 'offline' ? 'Ngoại tuyến' : 'Không rõ'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-sm text-muted-foreground">Không tìm thấy thiết bị nào</div>
        )}
      </div>
    </div>
  );
};

export default AssetsPage;
