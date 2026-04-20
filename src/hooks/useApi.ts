import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, ScanStartRequest, AssetFilterParams } from '@/lib/api';

const STALE = 30_000; // 30s

// ── Read hooks ─────────────────────────────────────────────────────
export const useAssets          = (params: AssetFilterParams = {}) => useQuery({ queryKey: ['assets', params], queryFn: () => api.assets(params), staleTime: STALE });
export const useAsset           = (id: string) => useQuery({ queryKey: ['asset', id], queryFn: () => api.asset(id), enabled: !!id, staleTime: STALE });
export const useStats           = () => useQuery({ queryKey: ['stats'],        queryFn: api.stats,                           staleTime: STALE });
export const useConnections     = (limit = 200) => useQuery({ queryKey: ['connections', limit], queryFn: () => api.connections(limit), staleTime: STALE });
export const useDns             = (limit = 200) => useQuery({ queryKey: ['dns', limit],         queryFn: () => api.dns(limit),         staleTime: STALE });
export const useTls             = (limit = 200) => useQuery({ queryKey: ['tls', limit],         queryFn: () => api.tls(limit),         staleTime: STALE });
export const useHttp            = (limit = 200) => useQuery({ queryKey: ['http', limit],        queryFn: () => api.http(limit),        staleTime: STALE });
export const useBehaviors       = () => useQuery({ queryKey: ['behaviors'],    queryFn: api.behaviors,                       staleTime: STALE });
export const useInferenceSummary = () => useQuery({ queryKey: ['inferenceSummary'], queryFn: api.inferenceSummary,           staleTime: STALE });
export const useBehaviorSummary = () => useQuery({ queryKey: ['behaviorSummary'], queryFn: api.behaviorSummary,             staleTime: STALE });
export const useConfidenceDistribution = () => useQuery({ queryKey: ['confidenceDistribution'], queryFn: api.confidenceDistribution, staleTime: STALE });
export const useAnomalySummary  = () => useQuery({ queryKey: ['anomalySummary'], queryFn: api.anomalySummary,               staleTime: STALE });
export const useTopology        = () => useQuery({ queryKey: ['topology'],     queryFn: api.topology,                        staleTime: STALE, refetchInterval: 60_000 });
export const useHealth          = () => useQuery({ queryKey: ['health'],       queryFn: api.health,                          staleTime: 5_000, refetchInterval: 5_000 });

export const useAlerts = (params?: { status?: string; type?: string; severity?: string; limit?: number; offset?: number }) =>
  useQuery({ queryKey: ['alerts', params], queryFn: () => api.alerts(params), staleTime: STALE });

export const useAlertCounts = () =>
  useQuery({ queryKey: ['alertCounts'], queryFn: api.alertCounts, staleTime: STALE });

export const useVulnerabilities = (params?: { severity?: string; limit?: number; offset?: number }) =>
  useQuery({ queryKey: ['vulnerabilities', params], queryFn: () => api.vulnerabilities(params), staleTime: STALE });

export const useScanStatus = () =>
  useQuery({ queryKey: ['scanStatus'], queryFn: api.scanStatus, staleTime: 5_000, refetchInterval: 5_000 });

export const useNvdIntegration = () =>
  useQuery({ queryKey: ['nvdIntegration'], queryFn: api.nvdGet, staleTime: STALE, retry: false });

// ── Mutation hooks ─────────────────────────────────────────────────

export const useCreateAsset = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createAsset,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  });
};

export const useUpdateAsset = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof api.updateAsset>[1] }) =>
      api.updateAsset(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  });
};

export const useDeleteAsset = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteAsset(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  });
};

export const useUpdateAlert = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: string; note?: string }) => api.updateAlert(id, status, note),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['alertCounts'] });
    },
  });
};

export const useScanStart = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body?: ScanStartRequest) => api.scanStart(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scanStatus'] }),
  });
};

export const useScanStop = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.scanStop(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scanStatus'] }),
  });
};

export const useNvdSave = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (api_key: string) => api.nvdSave(api_key),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['nvdIntegration'] }),
  });
};

export const useNvdSync = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.nvdSync(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] });
      qc.invalidateQueries({ queryKey: ['asset'] });
      qc.invalidateQueries({ queryKey: ['vulnerabilities'] });
    },
  });
};

export const useNvdTest = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.nvdTest(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] });
      qc.invalidateQueries({ queryKey: ['asset'] });
      qc.invalidateQueries({ queryKey: ['vulnerabilities'] });
    },
  });
};
