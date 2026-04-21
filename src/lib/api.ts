import { authStorage } from './auth';

const API_BASE = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') || '/api';

function buildApiUrl(path: string, params?: Record<string, string | number | undefined | null>): string {
  const url = new URL(`${API_BASE}${path}`, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v === undefined || v === null || v === '') return;
      url.searchParams.set(k, String(v));
    });
  }
  return url.toString();
}

function buildAbsoluteUrl(path: string): string {
  return new URL(path, window.location.origin).toString();
}

function authHeaders(): HeadersInit {
  const token = authStorage.getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Generic GET — automatically attaches the Bearer token. */
async function get<T>(path: string, params?: Record<string, string | number | undefined | null>): Promise<T> {
  const res = await fetch(buildApiUrl(path, params), { headers: authHeaders() });
  if (res.status === 401) { authStorage.clear(); window.location.href = '/login'; throw new Error('Unauthorized'); }
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return res.json();
}

/** Generic POST / PATCH / DELETE — automatically attaches the Bearer token. */
async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    method,
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { authStorage.clear(); window.location.href = '/login'; throw new Error('Unauthorized'); }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `API ${method} ${path} → ${res.status}`);
  }
  // 204 No Content or empty body
  const text = await res.text();
  return text ? JSON.parse(text) : ({} as T);
}

export interface AssetRow {
  id: string;
  mac: string;
  vendor: string | null;
  first_seen: string;
  last_seen: string;
  asset_status: string;
  confidence_score: number;
  ip: string | null;
  hostname: string | null;
  user_agent: string | null;
  ja3: string | null;
  dhcp_vendor: string | null;
  protocols: string[] | null;
  ports: number[] | null;
  connection_count: string;
  // inference fields
  deviceType: string | null;
  os: string | null;
  osVersion: string | null;
  cpe: string | null;
  confidence: number | null;
  inference_method: string | null;
  behavior_type: string | null;
  anomaly_count: number;
  anomaly_high: number;
  vuln_count: number;
  max_cvss: number;
  open_ports: number;
  status: 'online' | 'offline' | null;
}

export interface InferenceSummaryRow {
  device_type: string;
  count: string;
  avg_confidence: string;
}

export interface BehaviorSummaryRow {
  behavior_type: string;
  count: number;
}

export interface ConfidenceDistribution {
  high: number;
  medium: number;
  low: number;
  very_low: number;
}

export interface AnomalySummary {
  total: number;
  high: number;
  medium: number;
  low: number;
  affected_assets: number;
}

export interface InferenceResult {
  id: string;
  device_type: string | null;
  os: string | null;
  os_version: string | null;
  cpe: string | null;
  confidence: number | null;
  method: string | null;
  behavior_type: string | null;
  created_at: string | null;
}

export interface InferenceEvidence {
  evidence_type: string;
  value: string;
  weight: number;
}

export interface AssetAnomaly {
  anomaly_id: string;
  severity: 'high' | 'medium' | 'low';
  message: string;
  evidence: Record<string, unknown>;
}

export interface AssetVulnerability {
  cve_id: string | null;
  cvss_score: number | null;
  severity: string | null;
  description: string | null;
  detected_at: string | null;
}

export interface AssetDetail extends AssetRow {
  mac_address: string | null;
  ips: { ip: string; first_seen: string; last_seen: string }[];
  hostnames: { hostname: string; source: string }[];
  behaviors: { protocol: string; port: number; service: string; frequency: number }[];
  fingerprints: { ja3: string; ja3s: string; user_agent: string; dhcp_vendor: string }[];
  tls_server_names: string[];
  inference: InferenceResult | null;
  inference_evidence: InferenceEvidence[] | null;
  anomalies: AssetAnomaly[] | null;
  vulnerabilities: AssetVulnerability[] | null;
}

export interface StatsResponse {
  assets: { total: string; active: string; ip_only: string; has_mac: string };
  connections: { total: string; unique_src: string; unique_dst: string; total_bytes_sent: string; total_bytes_recv: string };
  dns: { total: string; unique_assets: string };
  tls: { total: string; unique_assets: string };
  http: { total: string; unique_assets: string };
  topProtocols: { protocol: string; count: string }[];
  topAssets: { id: string; mac_address: string; vendor: string; confidence_score: number; ip: string; conn_count: string }[];
  trafficByHour: { hour: string; bytes_out: string; bytes_in: string; conn_count: string }[];
}

export interface ConnectionRow {
  id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  service: string | null;
  duration: number | null;
  bytes_sent: number | null;
  bytes_received: number | null;
  timestamp: string;
  src_vendor: string | null;
  dst_vendor: string | null;
}

export interface DnsRow {
  id: string;
  query: string;
  answer: string | null;
  query_type: string | null;
  timestamp: string;
  src_ip: string | null;
}

export interface TlsRow {
  id: string;
  server_name: string | null;
  version: string | null;
  ja3: string | null;
  ja3s: string | null;
  certificate_issuer: string | null;
  next_protocol: string | null;
  validation_status: string | null;
  sni_matches_cert: boolean | null;
  ssl_history: string | null;
  timestamp: string;
  src_ip: string | null;
}

export interface HttpRow {
  id: string;
  host: string | null;
  uri: string | null;
  method: string | null;
  status_code: number | null;
  user_agent: string | null;
  timestamp: string;
  src_ip: string | null;
}

export interface BehaviorRow {
  protocol: string;
  port: number | null;
  service: string | null;
  total_frequency: string;
  asset_count: string;
}

// ── Topology ────────────────────────────────────────────────────────

export interface TopologyNode {
  id: string;
  ip: string | null;
  hostname: string | null;
  device_type: string;
  vendor: string | null;
  status: 'online' | 'offline';
  behavior_type?: string | null;
  confidence?: number | null;
  vuln_count?: number | null;
  max_cvss?: number | null;
  last_seen?: string | null;
}

export interface TopologyVlan {
  id: string;
  name: string;
  cidr: string;
  node_count: number;
  nodes: TopologyNode[];
}

export interface TopologyConnection {
  src_id: string;
  dst_id: string;
  protocol: string | null;
  service: string | null;
  count: number;
  bytes: number;
}

export interface TopologyResponse {
  vlans: TopologyVlan[];
  connections: TopologyConnection[];
  stats: {
    total_vlans: number;
    total_nodes: number;
    total_connections: number;
  };
}

// ── Demo Data Generator ─────────────────────────────────────────────

export type DeviceType = 'IoMT' | 'IoT' | 'Workstation' | 'Server' | 'Network' | 'Unknown';

export interface VlanConfig {
  vlan_id: number;
  name: string;
  subnet: string;
  device_type: DeviceType;
  device_count: number;
}

export interface NetworkConfig {
  org_name: string;
  domain: string;
  dns_server: string;
  vlans: VlanConfig[];
  simulate_days: number;
  events_per_device: number;
}

export interface GenerateResult {
  status: string;
  files_written: string[];
  device_counts: Record<string, number>;
  total_devices: number;
  total_events: number;
  log_dir: string;
  message: string;
}

export interface GeneratorStatus {
  zeek_log_dir: string;
  generated_dirs: string[];
  last_generated: string | null;
  total_assets_in_db: number;
}

export async function runGenerator(config: NetworkConfig): Promise<GenerateResult> {
  const res = await fetch(buildApiUrl('/generator/run'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(config),
    signal: AbortSignal.timeout(180000),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `API /generator/run → ${res.status}`);
  }
  return res.json();
}

export interface AssetFilterParams {
  limit?: number;
  offset?: number;
  sort?: string;
  device_type?: string;
  behavior_type?: string;
  search?: string;
  status?: string;
  vendor?: string;
  has_anomaly?: boolean;
  has_vuln?: boolean;
  min_confidence?: number;
  max_confidence?: number;
}

export interface PaginatedAssets {
  items: AssetRow[];
  total: number;
}

// ── Alerts ─────────────────────────────────────────────────────────

export interface AlertItem {
  id: string;
  alert_type: string;
  severity: string;
  message: string;
  source_ip: string | null;
  asset_id: string | null;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  metadata: Record<string, unknown> | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface PaginatedAlerts {
  items: AlertItem[];
  total: number;
}

export interface AlertCounts {
  total?: number;
  by_status: { status: string; count: number }[];
  by_severity: { severity: string; count: number }[];
  critical_vulns_active?: number;
}

// ── Vulnerabilities ────────────────────────────────────────────────

export interface VulnerabilityItem {
  id: string;
  cve_id: string | null;
  cvss_score: number | null;
  severity: string | null;
  description: string | null;
  affected_assets: number;
}

export interface PaginatedVulnerabilities {
  items: VulnerabilityItem[];
  total: number;
}

// ── Scan ───────────────────────────────────────────────────────────

export interface ScanStatus {
  mode: string;
  status: string;
  running: boolean;
  job_id: string | null;
  interface: string | null;
  log_dir: string | null;
  logs_processed: number;
  assets_discovered: number;
  ingestion_rate: number;
  started_at: string | null;
  stopped_at: string | null;
  error: string | null;
}

export interface HealthScanSummary {
  status: string;
  running?: boolean;
  mode?: string | null;
  job_id?: string | null;
  interface?: string | null;
  log_dir?: string | null;
  logs_processed?: number;
  assets_discovered?: number;
  ingestion_rate?: number;
  started_at?: string | null;
  stopped_at?: string | null;
  error?: string | null;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  database: {
    connected: boolean;
    latency_ms: number | null;
    error?: string;
  };
  zeek: {
    running: boolean;
    note?: string;
  };
  ingestion: {
    status: 'running' | 'stopped';
    events_per_sec: number;
    last_log_timestamp: string | null;
  };
  assets: {
    total: number;
    classified: number;
    unknown: number;
  };
  // Legacy fields — kept for backward compatibility with older clients.
  total_assets: number;
  last_log_timestamp: string | null;
  scan: HealthScanSummary;
  zeek_process: {
    running: boolean;
    note?: string;
  };
}

export interface ScanStartRequest {
  mode?: 'file' | 'live';
  log_dir?: string;
  interface?: string;
}

// ── NVD Integration ────────────────────────────────────────────────

export interface NvdIntegration {
  configured: boolean;
  last_sync_at: string | null;
}

export interface NvdMutationResponse {
  status: string;
  message: string;
}

export interface NvdTestResponse {
  status: string;
  cpes_checked: number;
  cves_found: number;
  assets_linked: number;
  elapsed_seconds: number;
  total_cpes: number;
  api_key_used: boolean;
  sample_cves: {
    cve_id: string;
    cvss_score: number;
    severity: string;
    cpe: string;
    published?: string;
  }[];
}

export interface NvdGenerateAlertsResponse {
  status: string;
  alerts_created: number;
  rows_found?: number;
  total_asset_vuln_links: number;
  existing_vuln_alerts: number;
  total_vuln_alerts_after?: number;
  message: string;
}

// ── Auth ───────────────────────────────────────────────────────────

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface UserInfo {
  username: string;
  role: 'admin' | 'analyst';
}

export interface AdminUser {
  id: string;
  username: string;
  role: 'admin' | 'analyst';
  is_active: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface CreateUserRequest {
  username: string;
  password: string;
  role: 'admin' | 'analyst';
}

export interface UpdateUserRequest {
  role?: 'admin' | 'analyst';
  is_active?: boolean;
  password?: string;
}

export const api = {
  health: async () => {
    const res = await fetch(buildAbsoluteUrl('/health'), { headers: authHeaders() });
    if (res.status === 401) { authStorage.clear(); window.location.href = '/login'; throw new Error('Unauthorized'); }
    if (!res.ok) throw new Error(`API /health → ${res.status}`);
    return res.json() as Promise<HealthResponse>;
  },

  // Assets
  assets: (params: AssetFilterParams = {}) => {
    const q: Record<string, string | number> = {};
    q.limit = params.limit ?? 20;
    q.offset = params.offset ?? 0;
    q.sort = params.sort ?? 'confidence_desc';
    if (params.device_type) q.device_type = params.device_type;
    if (params.behavior_type) q.behavior_type = params.behavior_type;
    if (params.search) q.search = params.search;
    if (params.status) q.status = params.status;
    if (params.vendor) q.vendor = params.vendor;
    if (params.has_anomaly !== undefined) q.has_anomaly = params.has_anomaly ? 1 : 0;
    if (params.min_confidence !== undefined) q.min_confidence = params.min_confidence;
    if (params.max_confidence !== undefined) q.max_confidence = params.max_confidence;
    return get<PaginatedAssets>('/assets', q);
  },
  asset: (id: string) => get<AssetDetail>(`/assets/${id}`),
  createAsset: (body: { mac_address: string; ip_address?: string; vendor?: string; hostname?: string }) =>
    request<AssetRow>('POST', '/assets', body),
  updateAsset: (id: string, body: { mac_address?: string; ip_address?: string; vendor?: string; hostname?: string }) =>
    request<{ id: string; status: string }>('PUT', `/assets/${id}`, body),
  deleteAsset: (id: string) =>
    request<{ id: string; status: string }>('DELETE', `/assets/${id}`),

  // Stats / charts
  stats: () => get<StatsResponse>('/stats'),
  connections: (limit = 200) => get<ConnectionRow[]>('/connections', { limit }),
  dns: (limit = 200) => get<DnsRow[]>('/dns', { limit }),
  tls: (limit = 200) => get<TlsRow[]>('/tls', { limit }),
  http: (limit = 200) => get<HttpRow[]>('/http', { limit }),
  behaviors: () => get<BehaviorRow[]>('/behaviors'),
  inferenceSummary: () => get<InferenceSummaryRow[]>('/inference/summary'),
  behaviorSummary: () => get<BehaviorSummaryRow[]>('/inference/behavior-summary'),
  confidenceDistribution: () => get<ConfidenceDistribution>('/inference/confidence-distribution'),
  anomalySummary: () => get<AnomalySummary>('/inference/anomaly-summary'),
  topology: () => get<TopologyResponse>('/topology'),
  generatorStatus: () => get<GeneratorStatus>('/generator/status'),
  runGenerator,

  // Alerts
  alerts: (params?: { status?: string; type?: string; severity?: string; limit?: number; offset?: number }) =>
    get<PaginatedAlerts>('/alerts', params as Record<string, string | number>),
  alertCounts: () => get<AlertCounts>('/alerts/counts'),
  updateAlert: (id: string, status: string, note?: string) =>
    request<AlertItem>('PATCH', `/alerts/${id}`, note !== undefined ? { status, note } : { status }),

  // Vulnerabilities
  vulnerabilities: (params?: { severity?: string; limit?: number; offset?: number }) =>
    get<PaginatedVulnerabilities>('/vulnerabilities', params as Record<string, string | number>),

  // Scan
  scanStatus: () => get<ScanStatus>('/scan/status'),
  scanStart: (body?: ScanStartRequest) => request<ScanStatus>('POST', '/scan/start', body),
  scanStop: () => request<ScanStatus>('POST', '/scan/stop'),
  scanRestart: (body?: ScanStartRequest) => request<ScanStatus>('POST', '/scan/restart', body),

  // NVD Integration
  nvdGet: () => get<NvdIntegration>('/integrations/nvd'),
  nvdSave: (api_key: string) => request<NvdMutationResponse>('POST', '/integrations/nvd', { api_key }),
  nvdSync: () => request<NvdMutationResponse>('POST', '/integrations/nvd/sync'),
  nvdTest: () => request<NvdTestResponse>('POST', '/integrations/nvd/test'),
  nvdGenerateAlerts: () => request<NvdGenerateAlertsResponse>('POST', '/integrations/nvd/generate-alerts'),

  // Reports
  reportSubnets: () =>
    get<{ subnets: { cidr: string; node_count: number }[] }>('/reports/subnets'),
  reportHtml: async (
    opts: { download?: boolean; subnets?: string[] } = {},
  ): Promise<{ blobUrl: string; filename: string }> => {
    const url = buildApiUrl('/reports/html', {
      download: opts.download ? 1 : undefined,
      subnets: opts.subnets && opts.subnets.length > 0 ? opts.subnets.join(',') : undefined,
    });
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) { authStorage.clear(); window.location.href = '/login'; throw new Error('Unauthorized'); }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(text || `API /reports/html → ${res.status}`);
    }
    const blob = await res.blob();
    const filename = (res.headers.get('Content-Disposition') || '')
      .match(/filename="([^"]+)"/)?.[1]
      ?? `hospital-shield-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.html`;
    return { blobUrl: URL.createObjectURL(blob), filename };
  },

  // Auth
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const form = new URLSearchParams();
    form.append('username', username);
    form.append('password', password);
    const res = await fetch(buildApiUrl('/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(text || `Login failed: ${res.status}`);
    }
    return res.json();
  },
  me: () => get<UserInfo>('/auth/me'),
  createUser: (body: CreateUserRequest) => request<UserInfo>('POST', '/auth/users', body),
  listUsers: () => get<AdminUser[]>('/auth/users'),
  updateUser: (id: string, body: UpdateUserRequest) =>
    request<AdminUser>('PATCH', `/auth/users/${id}`, body),
  deleteUser: (id: string) => request<void>('DELETE', `/auth/users/${id}`),
};
