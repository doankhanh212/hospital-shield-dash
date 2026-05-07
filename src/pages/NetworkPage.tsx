import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import {
  Network,
  ArrowRightLeft,
  RefreshCw,
  Share2,
  Activity,
  Monitor,
  HeartPulse,
  Camera,
  Server,
  Router,
  HelpCircle,
  ZoomIn,
  ZoomOut,
  Maximize2,
} from 'lucide-react';
import PageHeader from '@/components/widgets/PageHeader';
import { ChartSkeleton, TableSkeleton } from '@/components/widgets/Skeletons';
import { useChartTheme } from '@/hooks/useChartTheme';
import { useConnections, useBehaviors, useTopology } from '@/hooks/useApi';
import type { TopologyNode, TopologyConnection, TopologyVlan } from '@/lib/api';
import AssetTooltip from '@/components/network/AssetTooltip';
import LiveThreatStrip from '@/components/xdr/LiveThreatStrip';
import { format } from 'date-fns';

const HOVER_DELAY_MS = 100;

/**
 * Compact IP label that fits the 56-px grid cell:
 *   IPv4 → ".<last octet>" (e.g. 192.168.100.184 → ".184")
 *   IPv6 → "…<last 4 hex>"
 *   anything else (hostname, missing) → first 8 chars
 * Full address is still surfaced via the AssetTooltip.
 */
const shortLabel = (ip: string | null | undefined): string => {
  if (!ip) return '—';
  if (/^\d+\.\d+\.\d+\.\d+/.test(ip)) {
    const parts = ip.split('.');
    return '.' + parts[parts.length - 1];
  }
  if (ip.includes(':')) {
    const tail = ip.split(':').filter(Boolean).pop() ?? '';
    return '…' + tail.slice(-4);
  }
  return ip.slice(0, 8);
};

const fmtBytes = (b: number | null) => {
  if (!b) return '—';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
};

// ── Device type styling for topology ─────────────────────────────
const DEVICE_TYPE_COLOR: Record<string, string> = {
  IoMT:        '#3b82f6', // blue
  IoT:         '#f59e0b', // amber
  Workstation: '#6b7280', // gray
  Server:      '#8b5cf6', // purple
  Network:     '#10b981', // emerald
  Unknown:     '#ef4444', // red
};

const DEVICE_TYPE_ICON: Record<string, React.ElementType> = {
  IoMT:        HeartPulse,
  IoT:         Camera,
  Workstation: Monitor,
  Server:      Server,
  Network:     Router,
  Unknown:     HelpCircle,
};

// Connection-line color by protocol
const PROTOCOL_COLOR = (protocol: string | null, service: string | null): string => {
  const p = (protocol || '').toLowerCase();
  const s = (service || '').toLowerCase();
  if (s.includes('http') || s === 'ssl' || s === 'https') return '#3b82f6'; // blue
  if (s === 'dns')                                        return '#10b981'; // emerald
  if (p === 'udp')                                        return '#f59e0b'; // amber
  if (p === 'tcp')                                        return '#8b5cf6'; // purple
  return '#6b7280'; // gray fallback
};

type TabKey = 'topology' | 'connections' | 'protocols';

const NetworkPage = () => {
  const chart = useChartTheme();
  const [tab, setTab] = useState<TabKey>('topology');

  const { data: connections = [], isLoading: loadingConn, refetch: refetchConn } = useConnections(1000);
  const { data: behaviors = [],   isLoading: loadingBeh  } = useBehaviors();
  const { data: topology, isLoading: loadingTopo, refetch: refetchTopo } = useTopology();

  const isLoading =
    (tab === 'connections' && loadingConn) ||
    (tab === 'protocols'   && loadingBeh) ||
    (tab === 'topology'    && loadingTopo);

  // Top ports from behaviors
  const topPorts = behaviors
    .filter(b => b.port !== null)
    .slice(0, 10)
    .map(b => ({
      name: b.port ? `${b.port}/${b.protocol}` : b.protocol,
      count: Number(b.total_frequency),
      assets: Number(b.asset_count),
    }));

  const tabs: { key: TabKey; label: string; icon: React.ElementType }[] = [
    { key: 'topology',    label: 'Graph View',    icon: Share2 },
    { key: 'connections', label: 'Flow View',     icon: ArrowRightLeft },
    { key: 'protocols',   label: 'Protocol View', icon: Activity },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Sơ đồ mạng"
        description="Topology, luồng kết nối và phân bố giao thức trong cùng một nơi"
        actions={
          <button
            onClick={() => (tab === 'topology' ? refetchTopo() : refetchConn())}
            className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw size={13} /> Làm mới
          </button>
        }
      />

      <LiveThreatStrip />

      {/* Tab bar */}
      <div className="flex items-center gap-1.5 border-b border-border">
        {tabs.map(t => {
          const Icon = t.icon;
          const active = tab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2.5 text-[13px] font-medium transition-all -mb-px border-b-2 ${
                active
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
            >
              <Icon size={14} />
              {t.label}
            </button>
          );
        })}
      </div>

      {isLoading ? (
        tab === 'topology' ? (
          <ChartSkeleton />
        ) : (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <TableSkeleton rows={6} cols={4} />
            <ChartSkeleton />
          </div>
        )
      ) : tab === 'connections' ? (
        <div className="rounded-lg border border-border bg-card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
            <ArrowRightLeft size={15} className="text-primary" />
            Luồng kết nối ({connections.length})
          </h3>
          <div className="space-y-1.5 max-h-[560px] overflow-y-auto pr-1">
            {connections.map(c => (
              <div
                key={c.id}
                className="flex items-center justify-between rounded-lg border border-border/30 bg-muted/20 px-3 py-2 text-xs transition-colors hover:bg-accent/30"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-primary whitespace-nowrap">
                    {c.src_ip}:{c.src_port}
                  </span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono whitespace-nowrap">
                    {c.dst_ip}:{c.dst_port}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-3">
                  <span className="rounded-md bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                    {c.protocol}
                  </span>
                  <span className="text-muted-foreground text-[11px]">{fmtBytes(c.bytes_sent)}</span>
                  <span className="text-[10px] text-muted-foreground/60">
                    {c.timestamp ? format(new Date(c.timestamp), 'HH:mm') : ''}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : tab === 'topology' ? (
        <TopologyView data={topology} />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <div className="rounded-lg border border-border bg-card p-5">
            <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-foreground">
              <Network size={15} className="text-primary" />
              Top port / giao thức
            </h3>
            <ResponsiveContainer width="100%" height={360}>
              <BarChart data={topPorts} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                <XAxis type="number" stroke={chart.axisStroke} tick={chart.axisTick} />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke={chart.axisStroke}
                  tick={chart.axisTick}
                  width={110}
                />
                <Tooltip contentStyle={chart.tooltipStyle} formatter={(v: number) => v.toLocaleString()} />
                <Bar dataKey="count" name="Tần suất" fill={chart.colors.primary} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="rounded-lg border border-border bg-card p-5">
            <h3 className="mb-4 text-sm font-semibold text-foreground">Tóm tắt hành vi giao thức</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    <th className="pb-3 pr-4">Giao thức</th>
                    <th className="pb-3 pr-4">Port</th>
                    <th className="pb-3 pr-4">Dịch vụ</th>
                    <th className="pb-3 pr-4">Tần suất</th>
                    <th className="pb-3">Tài sản</th>
                  </tr>
                </thead>
                <tbody>
                  {behaviors.slice(0, 20).map((b, i) => (
                    <tr key={i} className="border-b border-border/30 hover:bg-accent/30 transition-colors">
                      <td className="py-2.5 pr-4">
                        <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[11px] font-medium text-primary">
                          {b.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-xs text-muted-foreground">
                        {b.port ?? '—'}
                      </td>
                      <td className="py-2.5 pr-4 text-xs">{b.service || '—'}</td>
                      <td className="py-2.5 pr-4 font-mono text-xs font-semibold">
                        {Number(b.total_frequency).toLocaleString()}
                      </td>
                      <td className="py-2.5 font-mono text-xs">{Number(b.asset_count).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ── Topology SVG view with zoom/pan + grid layout ───────────────

interface LaidOutNode extends TopologyNode {
  x: number;
  y: number;
  vlanId: string;
}

interface TopologyViewProps {
  data: import('@/lib/api').TopologyResponse | undefined;
}

// Grid layout constants
const GRID_CELL = 56;           // spacing between node centres in the grid
const GRID_PADDING = 80;        // horizontal padding inside VLAN box
const GRID_TOP_PAD = 56;        // space above first row of nodes (for label)
const GRID_BOT_PAD = 24;        // space below last row
const VLAN_GAP = 32;            // vertical gap between VLAN boxes
const NODE_R = 14;              // node circle radius
const COLS_MAX = 14;            // max nodes per row inside a VLAN

const MIN_ZOOM = 0.15;
const MAX_ZOOM = 3;

const TopologyView = ({ data }: TopologyViewProps) => {
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement>(null);

  // Zoom / pan state
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  // Collapsed VLANs
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  // Hover state
  const [hoverNode, setHoverNode] = useState<LaidOutNode | null>(null);
  const [hoverEdge, setHoverEdge] = useState<TopologyConnection | null>(null);
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const hoverTimerRef = useRef<number | null>(null);

  const scheduleHover = useCallback((n: LaidOutNode) => {
    if (hoverTimerRef.current != null) window.clearTimeout(hoverTimerRef.current);
    hoverTimerRef.current = window.setTimeout(() => setHoverNode(n), HOVER_DELAY_MS);
  }, []);

  const clearHover = useCallback(() => {
    if (hoverTimerRef.current != null) {
      window.clearTimeout(hoverTimerRef.current);
      hoverTimerRef.current = null;
    }
    setHoverNode(null);
  }, []);

  useEffect(() => {
    return () => {
      if (hoverTimerRef.current != null) window.clearTimeout(hoverTimerRef.current);
    };
  }, []);

  const toggleCollapse = (vlanId: string) => {
    setCollapsed(prev => {
      const next = new Set(prev);
      if (next.has(vlanId)) next.delete(vlanId);
      else next.add(vlanId);
      return next;
    });
  };

  // ── Layout: grid within each VLAN box ─────────────────────
  const { nodes, edges, totalWidth, totalHeight, nodeById, vlanBoxes } = useMemo(() => {
    if (!data) {
      return {
        nodes: [] as LaidOutNode[],
        edges: [] as TopologyConnection[],
        totalWidth: 800,
        totalHeight: 400,
        nodeById: new Map<string, LaidOutNode>(),
        vlanBoxes: [] as { id: string; name: string; x: number; y: number; w: number; h: number; nodeCount: number; breakdown: string }[],
      };
    }

    const laid: LaidOutNode[] = [];
    const map = new Map<string, LaidOutNode>();
    const boxes: { id: string; name: string; x: number; y: number; w: number; h: number; nodeCount: number; breakdown: string }[] = [];

    let curY = 24;

    data.vlans.forEach((vlan: TopologyVlan) => {
      const isCollapsed = collapsed.has(vlan.id);
      const count = vlan.nodes.length;
      const cols = Math.min(COLS_MAX, count);
      const rows = isCollapsed ? 0 : Math.ceil(count / cols);
      const boxW = Math.max(360, cols * GRID_CELL + GRID_PADDING * 2);
      const boxH = isCollapsed
        ? 48
        : GRID_TOP_PAD + rows * GRID_CELL + GRID_BOT_PAD;

      // Per-VLAN device-type breakdown for a more informative label
      const dtCounts: Record<string, number> = {};
      vlan.nodes.forEach(n => {
        const k = n.device_type || 'Unknown';
        dtCounts[k] = (dtCounts[k] || 0) + 1;
      });
      const breakdown = Object.entries(dtCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4)
        .map(([k, v]) => `${v} ${k}`)
        .join(' · ');

      boxes.push({
        id: vlan.id,
        name: vlan.name,
        x: 24,
        y: curY,
        w: boxW,
        h: boxH,
        nodeCount: count,
        breakdown,
      });

      if (!isCollapsed) {
        vlan.nodes.forEach((n: TopologyNode, idx: number) => {
          const col = idx % cols;
          const row = Math.floor(idx / cols);
          const nodeX = 24 + GRID_PADDING + col * GRID_CELL + GRID_CELL / 2;
          const nodeY = curY + GRID_TOP_PAD + row * GRID_CELL + GRID_CELL / 2;
          const laidNode: LaidOutNode = { ...n, x: nodeX, y: nodeY, vlanId: vlan.id };
          laid.push(laidNode);
          map.set(n.id, laidNode);
        });
      }

      curY += boxH + VLAN_GAP;
    });

    const maxBoxRight = boxes.reduce((mx, b) => Math.max(mx, b.x + b.w), 800);
    return {
      nodes: laid,
      edges: data.connections,
      totalWidth: maxBoxRight + 48,
      totalHeight: Math.max(400, curY),
      nodeById: map,
      vlanBoxes: boxes,
    };
  }, [data, collapsed]);

  // ── Wheel zoom (centred on cursor) ─────────────────────────
  const handleWheel = useCallback(
    (e: React.WheelEvent) => {
      e.preventDefault();
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;

      const cursorX = e.clientX - rect.left;
      const cursorY = e.clientY - rect.top;

      const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
      const newZoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, zoom * factor));
      const ratio = newZoom / zoom;

      setPan(p => ({
        x: cursorX - ratio * (cursorX - p.x),
        y: cursorY - ratio * (cursorY - p.y),
      }));
      setZoom(newZoom);
    },
    [zoom],
  );

  // ── Mouse drag pan ────────────────────────────────────────
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (e.button !== 0) return;
      setDragging(true);
      dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
    },
    [pan],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!dragging) return;
      const dx = e.clientX - dragStart.current.x;
      const dy = e.clientY - dragStart.current.y;
      setPan({ x: dragStart.current.panX + dx, y: dragStart.current.panY + dy });
    },
    [dragging],
  );

  const handleMouseUp = useCallback(() => setDragging(false), []);

  // Release drag if mouse leaves window
  useEffect(() => {
    const up = () => setDragging(false);
    window.addEventListener('mouseup', up);
    return () => window.removeEventListener('mouseup', up);
  }, []);

  // ── Fit-to-view ───────────────────────────────────────────
  const fitView = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    const containerW = el.clientWidth;
    const containerH = el.clientHeight;
    const padded = 48;
    const fitZoom = Math.min(
      (containerW - padded) / totalWidth,
      (containerH - padded) / totalHeight,
      1.5,
    );
    setZoom(Math.max(MIN_ZOOM, fitZoom));
    setPan({
      x: (containerW - totalWidth * fitZoom) / 2,
      y: (containerH - totalHeight * fitZoom) / 2,
    });
  }, [totalWidth, totalHeight]);

  // Auto-fit on first load
  const didFit = useRef(false);
  useEffect(() => {
    if (data && data.vlans.length > 0 && !didFit.current) {
      didFit.current = true;
      // small delay to let container measure
      requestAnimationFrame(() => fitView());
    }
  }, [data, fitView]);

  if (!data) {
    return (
      <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
        Không có dữ liệu sơ đồ mạng.
      </div>
    );
  }

  if (data.vlans.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
        Chưa có tài sản nội bộ nào được phát hiện. Hãy nạp thêm log Zeek hoặc chạy Setup Wizard để sinh bộ log thử nghiệm.
      </div>
    );
  }

  // Count device types for legend
  const typeCounts: Record<string, number> = {};
  data.vlans.forEach((v: TopologyVlan) =>
    v.nodes.forEach((n: TopologyNode) => {
      typeCounts[n.device_type] = (typeCounts[n.device_type] || 0) + 1;
    }),
  );

  const showLabels = zoom >= 0.55;

  return (
    <div className="space-y-4">
      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'VLAN', value: data.stats.total_vlans },
          { label: 'Thiết bị', value: data.stats.total_nodes },
          { label: 'Luồng kết nối', value: data.stats.total_connections },
        ].map(s => (
          <div key={s.label} className="rounded-lg border border-border bg-card p-4">
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{s.label}</p>
            <p className="mt-1 text-2xl font-bold text-foreground">{s.value}</p>
          </div>
        ))}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 text-xs">
        <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Loại thiết bị:</span>
        {(['IoMT', 'IoT', 'Workstation', 'Server', 'Network', 'Unknown'] as const).map(t => {
          const Icon = DEVICE_TYPE_ICON[t];
          return (
            <span key={t} className="flex items-center gap-1.5">
              <span
                className="flex h-5 w-5 items-center justify-center rounded-full"
                style={{ backgroundColor: DEVICE_TYPE_COLOR[t] + '20', color: DEVICE_TYPE_COLOR[t] }}
              >
                <Icon size={11} />
              </span>
              <span className="text-foreground">{t}</span>
              <span className="text-muted-foreground">({typeCounts[t] || 0})</span>
            </span>
          );
        })}
      </div>

      {/* SVG diagram with zoom/pan */}
      <div className="rounded-lg border border-border bg-card overflow-hidden relative">
        {/* Zoom controls */}
        <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
          <button
            onClick={() => setZoom(z => Math.min(MAX_ZOOM, z * 1.3))}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            title="Phóng to"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={() => setZoom(z => Math.max(MIN_ZOOM, z / 1.3))}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            title="Thu nhỏ"
          >
            <ZoomOut size={14} />
          </button>
          <button
            onClick={fitView}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            title="Vừa khung hình"
          >
            <Maximize2 size={14} />
          </button>
        </div>

        {/* Zoom indicator */}
        <div className="absolute bottom-3 right-3 z-10 rounded-md bg-card/90 border border-border px-2 py-1 text-[10px] text-muted-foreground font-mono">
          {Math.round(zoom * 100)}%
        </div>

        <div
          ref={containerRef}
          className="w-full select-none"
          style={{ height: 600, overflow: 'hidden', cursor: dragging ? 'grabbing' : 'grab' }}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          <svg
            width="100%"
            height="100%"
            style={{ display: 'block' }}
          >
            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* VLAN boxes */}
              {vlanBoxes.map(box => {
                const isCol = collapsed.has(box.id);
                return (
                  <g key={box.id}>
                    <rect
                      x={box.x}
                      y={box.y}
                      width={box.w}
                      height={box.h}
                      rx={10}
                      fill="currentColor"
                      stroke="currentColor"
                      strokeWidth={0.5}
                      className="text-muted/20"
                    />
                    {/* Collapse toggle + label */}
                    <g
                      onClick={(e) => { e.stopPropagation(); toggleCollapse(box.id); }}
                      style={{ cursor: 'pointer' }}
                    >
                      <rect
                        x={box.x}
                        y={box.y}
                        width={box.w}
                        height={40}
                        rx={10}
                        fill="transparent"
                      />
                      {/* Chevron */}
                      <g transform={`translate(${box.x + 16}, ${box.y + 14})`}>
                        {isCol ? (
                          <polygon
                            points="0,0 8,5 0,10"
                            fill="currentColor"
                            className="text-muted-foreground"
                          />
                        ) : (
                          <polygon
                            points="0,0 10,0 5,8"
                            fill="currentColor"
                            className="text-muted-foreground"
                          />
                        )}
                      </g>
                      <text
                        x={box.x + 34}
                        y={box.y + 22}
                        className="fill-muted-foreground"
                        style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.05em' }}
                      >
                        {box.name}
                      </text>
                      <text
                        x={box.x + 34}
                        y={box.y + 36}
                        className="fill-muted-foreground"
                        style={{ fontSize: 10 }}
                      >
                        {box.nodeCount} thiết bị{box.breakdown ? ` — ${box.breakdown}` : ''}
                      </text>
                    </g>
                  </g>
                );
              })}

              {/* Edges */}
              {edges.map((e, i) => {
                const src = nodeById.get(e.src_id);
                const dst = nodeById.get(e.dst_id);
                if (!src || !dst) return null;
                const color = PROTOCOL_COLOR(e.protocol, e.service);
                const sw = Math.min(3, 0.5 + Math.log10(Math.max(1, e.count)) * 0.8);
                const isHover = hoverEdge === e;
                return (
                  <line
                    key={`e-${i}`}
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke={color}
                    strokeWidth={sw / zoom} // keep visual weight stable
                    strokeOpacity={isHover ? 0.9 : 0.25}
                    onMouseEnter={() => setHoverEdge(e)}
                    onMouseLeave={() => setHoverEdge(null)}
                    style={{ cursor: 'pointer', pointerEvents: 'stroke' }}
                  />
                );
              })}

              {/* Nodes */}
              {nodes.map((n: LaidOutNode) => {
                const color = DEVICE_TYPE_COLOR[n.device_type] || DEVICE_TYPE_COLOR.Unknown;
                const isHover = hoverNode?.id === n.id;
                const r = NODE_R;
                return (
                  <g
                    key={n.id}
                    transform={`translate(${n.x}, ${n.y})`}
                    onMouseEnter={(e) => {
                      setCursor({ x: e.clientX, y: e.clientY });
                      scheduleHover(n);
                    }}
                    onMouseMove={(e) => setCursor({ x: e.clientX, y: e.clientY })}
                    onMouseLeave={clearHover}
                    onClick={(e) => { e.stopPropagation(); navigate(`/assets/${n.id}`); }}
                    style={{ cursor: 'pointer' }}
                  >
                    {isHover && (
                      <circle r={r + 6} fill={color} fillOpacity={0.15} />
                    )}
                    <circle
                      r={r}
                      fill={color}
                      fillOpacity={0.85}
                      stroke={isHover ? '#ffffff' : color}
                      strokeWidth={isHover ? 2 : 1}
                    />
                    {n.status === 'online' && (
                      <circle
                        cx={r - 2}
                        cy={-r + 2}
                        r={3}
                        fill="#10b981"
                        stroke="#ffffff"
                        strokeWidth={0.8}
                      />
                    )}
                    {showLabels && (
                      <text
                        y={r + 12}
                        textAnchor="middle"
                        className="fill-foreground"
                        style={{ fontSize: 9, fontFamily: 'monospace' }}
                      >
                        {shortLabel(n.ip)}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Edge hover bar */}
        {!hoverNode && hoverEdge && (
          <div className="border-t border-border bg-muted/30 px-4 py-2 text-xs flex items-center gap-4">
            <span className="text-muted-foreground">Luồng:</span>
            <span className="font-mono text-foreground">
              {nodeById.get(hoverEdge.src_id)?.ip} → {nodeById.get(hoverEdge.dst_id)?.ip}
            </span>
            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
              {hoverEdge.protocol}{hoverEdge.service ? `/${hoverEdge.service}` : ''}
            </span>
            <span className="text-muted-foreground">{hoverEdge.count.toLocaleString()} kết nối</span>
            <span className="text-muted-foreground">{fmtBytes(hoverEdge.bytes)}</span>
          </div>
        )}
      </div>

      {/* Floating rich tooltip */}
      {hoverNode && <AssetTooltip node={hoverNode} position={cursor} />}
    </div>
  );
};

export default NetworkPage;
