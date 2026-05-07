/**
 * XDR Command Centre — real-time SOC view.
 *
 * Layout:
 *   ┌────────────────────────────────────────────────────────────────────┐
 *   │  KPI tiles (Total Assets · Conn · Alerts · Critical · Incidents)   │
 *   ├────────────────────────────────────────────────────────────────────┤
 *   │  Anomaly table (sortable / filterable / click → drawer)            │
 *   ├────────────────────────────┬───────────────────────────────────────┤
 *   │  Network map (radial)      │  Incident panel                       │
 *   └────────────────────────────┴───────────────────────────────────────┘
 *
 * Polls /api/xdr/anomalies and /api/xdr/incidents every 5 s via TanStack
 * Query.  New anomalies (since the prior tick) get a brief highlight pulse.
 */

import { useMemo, useState } from 'react';
import { Activity, AlertTriangle, Cpu, RadioTower, Server, ShieldAlert, ShieldQuestion } from 'lucide-react';

import EmptyState from '@/components/widgets/EmptyState';
import StatCard from '@/components/widgets/StatCard';
import AnomalyDetailDrawer from '@/components/xdr/AnomalyDetailDrawer';
import AnomalyTable from '@/components/xdr/AnomalyTable';
import IncidentPanel from '@/components/xdr/IncidentPanel';
import NetworkMiniMap from '@/components/xdr/NetworkMiniMap';

import { type XdrAnomaly } from '@/lib/xdr';
import { useAnomalies, useIncidents, useNewIds, useXdrKpis } from '@/hooks/useXdr';

const REFRESH_MS = 5_000;

const XdrPage = () => {
  const anomaliesQ = useAnomalies({ limit: 100 }, REFRESH_MS);
  const incidentsQ = useIncidents({ limit: 50 }, REFRESH_MS);

  const anomalies = anomaliesQ.data?.items ?? [];
  const incidents = incidentsQ.data?.items ?? [];
  const newIds    = useNewIds(anomalies);
  const kpi       = useXdrKpis(anomalies, incidents);

  const [selected, setSelected] = useState<XdrAnomaly | null>(null);

  const related = useMemo(
    () => (selected ? anomalies.filter(a => a.asset_id === selected.asset_id) : []),
    [selected, anomalies],
  );

  const isInitialLoading =
    (anomaliesQ.isLoading && !anomaliesQ.data) ||
    (incidentsQ.isLoading && !incidentsQ.data);

  const apiError =
    (anomaliesQ.error as Error | undefined)?.message ||
    (incidentsQ.error as Error | undefined)?.message;

  return (
    <div className="space-y-4">
      {/* Header */}
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-foreground">
            XDR Command Centre
          </h1>
          <p className="text-xs text-muted-foreground">
            Real-time anomaly &amp; incident view ·
            <span className="ml-1 inline-flex items-center gap-1">
              <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-success" />
              auto-refresh every {REFRESH_MS / 1000}s
            </span>
          </p>
        </div>
        {anomaliesQ.dataUpdatedAt > 0 && (
          <p className="text-[10px] text-muted-foreground">
            updated {new Date(anomaliesQ.dataUpdatedAt).toLocaleTimeString()}
          </p>
        )}
      </header>

      {apiError && (
        <div className="rounded-md border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">
          API error: {apiError}.  Check that the backend is running on port 3001.
        </div>
      )}

      {/* KPIs */}
      <section className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <StatCard
          title="Affected Assets"
          value={kpi.uniqueAssets}
          icon={Cpu}
          variant="info"
          trend="unique IPs in alerts"
        />
        <StatCard
          title="Active Connections"
          value={kpi.totalConn}
          icon={RadioTower}
          variant="default"
          trend="across current window"
        />
        <StatCard
          title="Active Alerts"
          value={kpi.activeAlerts}
          icon={Activity}
          variant={kpi.activeAlerts > 0 ? 'warning' : 'default'}
          trend={`${kpi.highAlerts} high`}
        />
        <StatCard
          title="Critical Alerts"
          value={kpi.criticalAlerts}
          icon={AlertTriangle}
          variant={kpi.criticalAlerts > 0 ? 'critical' : 'default'}
          trend="severity ≥ critical"
        />
        <StatCard
          title="Incidents"
          value={kpi.incidents}
          icon={ShieldAlert}
          variant={kpi.incidents > 0 ? 'critical' : 'default'}
          trend="≥ 2 types in 5 min"
        />
        <StatCard
          title="Rogue Devices"
          value={kpi.rogueDevices}
          icon={ShieldQuestion}
          variant={kpi.rogueDevices > 0 ? 'critical' : 'default'}
          trend="unknown MAC seen"
        />
      </section>

      {/* Empty-state banner when system has no data at all */}
      {!isInitialLoading && anomalies.length === 0 && incidents.length === 0 && (
        <div className="rounded-lg border border-border bg-card">
          <EmptyState
            icon={Server}
            title="System is monitoring network traffic"
            description="No anomalies detected yet. New events will appear here automatically."
          />
        </div>
      )}

      {/* Anomaly table */}
      {(anomalies.length > 0 || isInitialLoading) && (
        <AnomalyTable
          anomalies={anomalies}
          loading={isInitialLoading}
          newIds={newIds}
          selectedId={selected?.id ?? null}
          onSelect={setSelected}
          maxRows={100}
        />
      )}

      {/* Map + incidents (side by side on lg) */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <NetworkMiniMap
            anomalies={anomalies}
            selectedAssetId={selected?.asset_id ?? null}
            onSelectAsset={(ip) => {
              const first = anomalies.find(a => a.asset_id === ip);
              if (first) setSelected(first);
            }}
          />
        </div>
        <IncidentPanel
          incidents={incidents}
          loading={incidentsQ.isLoading && !incidentsQ.data}
          onSelectAsset={(ip) => {
            const first = anomalies.find(a => a.asset_id === ip);
            if (first) setSelected(first);
          }}
        />
      </section>

      {/* Detail drawer */}
      <AnomalyDetailDrawer
        anomaly={selected}
        related={related}
        onClose={() => setSelected(null)}
      />
    </div>
  );
};

export default XdrPage;
