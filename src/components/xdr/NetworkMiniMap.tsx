/**
 * Lightweight SVG network map.
 *
 * No external graph library — does a simple deterministic radial layout of
 * unique asset_ids and draws an edge to a synthetic "external" node when an
 * anomaly involves data exfiltration.  Nodes are colour-coded by the highest
 * severity of any anomaly that asset has produced.
 *
 * This is intentionally minimal: it gives the analyst a 2-second visual of
 * "which assets are hot right now" without a heavyweight force layout.
 */

import { useMemo } from 'react';

import EmptyState from '@/components/widgets/EmptyState';
import { type Severity, type XdrAnomaly, SEVERITY_RANK, SEVERITY_TW } from '@/lib/xdr';

interface Props {
  anomalies: XdrAnomaly[];
  selectedAssetId?: string | null;
  onSelectAsset?: (assetId: string) => void;
}

interface Node {
  id: string;
  x: number;
  y: number;
  severity: Severity;
  alertCount: number;
  device: string;
}

const NETWORK_RADIUS = 140;
const CENTER         = { x: 200, y: 170 };
const SVG_W = 400;
const SVG_H = 340;

function highestSeverity(anomalies: XdrAnomaly[]): Severity {
  let best: Severity = 'low';
  let bestRank = 0;
  for (const a of anomalies) {
    const r = SEVERITY_RANK[a.severity];
    if (r > bestRank) { bestRank = r; best = a.severity; }
  }
  return best;
}

const SEV_FILL: Record<Severity, string> = {
  critical: 'hsl(var(--critical))',
  high:     'hsl(var(--high))',
  medium:   'hsl(var(--medium))',
  low:      'hsl(var(--low))',
};

const NetworkMiniMap = ({ anomalies, selectedAssetId, onSelectAsset }: Props) => {
  const nodes = useMemo<Node[]>(() => {
    const grouped = new Map<string, XdrAnomaly[]>();
    for (const a of anomalies) {
      if (!grouped.has(a.asset_id)) grouped.set(a.asset_id, []);
      grouped.get(a.asset_id)!.push(a);
    }
    const ids = Array.from(grouped.keys());
    const N   = Math.max(1, ids.length);
    return ids.map((id, i) => {
      const angle = (2 * Math.PI * i) / N - Math.PI / 2;
      const list  = grouped.get(id)!;
      return {
        id,
        x: CENTER.x + NETWORK_RADIUS * Math.cos(angle),
        y: CENTER.y + NETWORK_RADIUS * Math.sin(angle),
        severity:   highestSeverity(list),
        alertCount: list.length,
        device:     list[0].asset?.device_type ?? 'unknown',
      };
    });
  }, [anomalies]);

  const hasData = nodes.length > 0;

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-foreground">
          Network Map
        </h2>
        <span className="text-[10px] text-muted-foreground">
          {nodes.length} active asset{nodes.length === 1 ? '' : 's'}
        </span>
      </div>

      {!hasData ? (
        <EmptyState
          title="No assets in alert state"
          description="Assets will appear here as soon as the pipeline detects anomalous behaviour."
        />
      ) : (
        <svg viewBox={`0 0 ${SVG_W} ${SVG_H}`} className="h-[340px] w-full">
          {/* Edges from each asset to the central network node */}
          {nodes.map(n => {
            const sel = selectedAssetId === n.id;
            return (
              <line
                key={`e-${n.id}`}
                x1={CENTER.x} y1={CENTER.y}
                x2={n.x}      y2={n.y}
                stroke={sel ? SEV_FILL[n.severity] : 'hsl(var(--border))'}
                strokeOpacity={sel ? 0.9 : 0.4}
                strokeWidth={sel ? 1.5 : 1}
              />
            );
          })}

          {/* Center "internal network" anchor */}
          <g>
            <circle cx={CENTER.x} cy={CENTER.y} r="22" fill="hsl(var(--muted))" stroke="hsl(var(--border))" />
            <text x={CENTER.x} y={CENTER.y + 4} textAnchor="middle"
              className="fill-muted-foreground" style={{ fontSize: 10, fontWeight: 600 }}>
              LAN
            </text>
          </g>

          {/* Asset nodes */}
          {nodes.map(n => {
            const sel  = selectedAssetId === n.id;
            const r    = sel ? 14 : 10 + Math.min(6, n.alertCount);
            return (
              <g key={n.id} style={{ cursor: 'pointer' }} onClick={() => onSelectAsset?.(n.id)}>
                <circle
                  cx={n.x} cy={n.y} r={r + 4}
                  fill={SEV_FILL[n.severity]}
                  fillOpacity={sel ? 0.35 : 0.18}
                  className={n.severity === 'critical' || n.severity === 'high' ? 'animate-pulse' : ''}
                />
                <circle
                  cx={n.x} cy={n.y} r={r}
                  fill={SEV_FILL[n.severity]}
                  stroke={sel ? 'hsl(var(--foreground))' : 'hsl(var(--background))'}
                  strokeWidth={sel ? 2 : 1.5}
                />
                <text
                  x={n.x}
                  y={n.y + r + 12}
                  textAnchor="middle"
                  className="fill-foreground"
                  style={{ fontSize: 10, fontFamily: 'monospace' }}
                >
                  {shortIp(n.id)}
                </text>
              </g>
            );
          })}

          {/* Legend */}
          <g transform="translate(8, 320)">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s, i) => (
              <g key={s} transform={`translate(${i * 64}, 0)`}>
                <circle cx="6" cy="-3" r="4" fill={SEV_FILL[s]} />
                <text x="14" y="0" className="fill-muted-foreground" style={{ fontSize: 9 }}>{s}</text>
              </g>
            ))}
          </g>
        </svg>
      )}
    </div>
  );
};

function shortIp(ip: string): string {
  // Trim IPv6 to last segment, leave IPv4 as-is
  if (ip.includes(':')) {
    const tail = ip.split(':').filter(Boolean).pop() ?? '';
    return `…${tail.slice(-6)}`;
  }
  return ip;
}

// Tailwind colour helpers — referenced here so the JIT extractor picks them up.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _ensureTwClasses = () => [
  SEVERITY_TW.critical, SEVERITY_TW.high, SEVERITY_TW.medium, SEVERITY_TW.low,
];

export default NetworkMiniMap;
