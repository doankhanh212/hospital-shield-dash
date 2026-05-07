/**
 * TanStack Query hooks for the XDR endpoints.
 *
 * Default refetch interval: 5s (overridable per call).  Designed to be
 * websocket-replaceable later — components consume the data via the same
 * shape regardless of how it arrives.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';

import {
  type AnomalyQuery,
  type Severity,
  type TriageStatus,
  type XdrAnomaly,
  type XdrIncident,
  xdrApi,
} from '@/lib/xdr';

const DEFAULT_REFRESH_MS = 5_000;

export function useAnomalies(q: AnomalyQuery = {}, refreshMs = DEFAULT_REFRESH_MS) {
  return useQuery({
    queryKey: ['xdr', 'anomalies', q],
    queryFn:  () => xdrApi.listAnomalies(q),
    refetchInterval: refreshMs,
    refetchOnWindowFocus: false,
    placeholderData: (prev) => prev,
  });
}

export function useIncidents(
  q: { asset_id?: string; severity?: Severity; limit?: number; offset?: number } = {},
  refreshMs = DEFAULT_REFRESH_MS,
) {
  return useQuery({
    queryKey: ['xdr', 'incidents', q],
    queryFn:  () => xdrApi.listIncidents(q),
    refetchInterval: refreshMs,
    refetchOnWindowFocus: false,
    placeholderData: (prev) => prev,
  });
}

/**
 * Track which anomaly IDs are *new* compared to the previous poll.  Useful
 * for highlight-on-arrival animation in the table.  Returns a Set of IDs
 * that were not present in the prior snapshot.
 */
export function useNewIds<T extends { id: string }>(items: T[] | undefined): Set<string> {
  const prevIds = useRef<Set<string>>(new Set());
  const [newIds, setNewIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!items) return;
    const current = new Set(items.map(i => i.id));
    if (prevIds.current.size === 0) {
      // First load — nothing is "new" yet
      prevIds.current = current;
      return;
    }
    const fresh = new Set<string>();
    for (const id of current) if (!prevIds.current.has(id)) fresh.add(id);
    if (fresh.size > 0) {
      setNewIds(fresh);
      const t = setTimeout(() => setNewIds(new Set()), 4_000);
      prevIds.current = current;
      return () => clearTimeout(t);
    }
    prevIds.current = current;
  }, [items]);

  return newIds;
}

// ── Asset timeline (audit + anomalies) ──────────────────────────────────────

export function useAssetTimeline(assetId: string | null | undefined, refreshMs = 5_000) {
  return useQuery({
    queryKey: ['xdr', 'timeline', assetId],
    queryFn:  () => xdrApi.timeline(assetId!),
    enabled:  !!assetId,
    refetchInterval: refreshMs,
    refetchOnWindowFocus: false,
    placeholderData: (prev) => prev,
  });
}

// ── Triage mutations (status / assign / note) ───────────────────────────────

/**
 * One mutation per action.  On success we invalidate anomaly + timeline
 * queries so every consumer (table, drawer, KPIs) refetches with fresh data.
 */
export function useTriageActions(anomalyId: string | undefined, assetId?: string | null) {
  const qc = useQueryClient();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['xdr', 'anomalies'] });
    qc.invalidateQueries({ queryKey: ['xdr', 'incidents'] });
    if (assetId) qc.invalidateQueries({ queryKey: ['xdr', 'timeline', assetId] });
  };

  const setStatus = useMutation({
    mutationFn: (status: TriageStatus) => xdrApi.setStatus(anomalyId!, status),
    onSuccess: invalidate,
  });

  const assign = useMutation({
    mutationFn: (user: string | null) => xdrApi.assign(anomalyId!, user),
    onSuccess: invalidate,
  });

  const addNote = useMutation({
    mutationFn: (note: string) => xdrApi.addNote(anomalyId!, note),
    onSuccess: invalidate,
  });

  return { setStatus, assign, addNote };
}

/**
 * Derive top-level KPIs from the anomaly + incident lists so the header
 * stays in sync with the same poll cycle (no separate request).
 */
export function useXdrKpis(
  anomalies: XdrAnomaly[] | undefined,
  incidents: XdrIncident[] | undefined,
) {
  const list = anomalies ?? [];
  const inc  = incidents ?? [];
  const uniqueAssets = new Set(list.map(a => a.asset_id)).size;
  const totalConn    = list.reduce((s, a) => s + (a.evidence?.conn_count ?? 0), 0);
  const critical     = list.filter(a => a.severity === 'critical').length;
  const high         = list.filter(a => a.severity === 'high').length;
  const rogueDevices = list.filter(a => a.type === 'rogue_device').length;
  return {
    uniqueAssets,
    totalConn,
    activeAlerts:  list.length,
    criticalAlerts: critical,
    highAlerts:    high,
    incidents:     inc.length,
    rogueDevices,
  };
}
