/**
 * Threat-intel API key cards for the Tích hợp page.
 * Drives the existing /api/xdr/settings backend (admin-protected).
 *
 * Two providers, identical UX:
 *   • VirusTotal     (key: VT_API_KEY)
 *   • AbuseIPDB      (key: ABUSEIPDB_API_KEY)
 *
 * Values returned from GET are server-side masked ("***xxxx") so the page
 * never exposes the raw secret after a refresh.
 */

import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertCircle, CheckCircle2, ExternalLink, Loader2, Save, ShieldAlert,
  ShieldCheck, Trash2, XCircle,
} from 'lucide-react';
import { toast } from 'sonner';

import { authStorage } from '@/lib/auth';

const API_BASE = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') || '/api';

type SettingKey = 'VT_API_KEY' | 'ABUSEIPDB_API_KEY';

interface SettingItem {
  key:        SettingKey | string;
  value:      string;        // masked, e.g. "***ab12"
  updated_at: string | null;
}

function authHeaders(): HeadersInit {
  const t = authStorage.getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function callJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(init?.headers || {}) },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `${path} → ${res.status}`);
  }
  return res.json();
}

const settingsApi = {
  list:   () => callJson<{ items: SettingItem[] }>('/xdr/settings'),
  upsert: (key: SettingKey, value: string) =>
    callJson<SettingItem>('/xdr/settings', { method: 'POST', body: JSON.stringify({ key, value }) }),
  remove: (key: SettingKey) =>
    callJson<{ deleted: string }>(`/xdr/settings/${key}`, { method: 'DELETE' }),
};

interface ProviderProps {
  k:        SettingKey;
  name:     string;
  desc:     string;
  helpUrl:  string;
  helpLabel: string;
  Icon:     typeof ShieldCheck;
  iconCls:  string;
}

const PROVIDERS: ProviderProps[] = [
  {
    k:        'VT_API_KEY',
    name:     'VirusTotal',
    desc:     'Tra cứu uy tín IP/Domain/URL — đếm số engine đánh dấu malicious / suspicious',
    helpUrl:  'https://www.virustotal.com/gui/my-apikey',
    helpLabel:'Lấy free API key từ VirusTotal',
    Icon:     ShieldCheck,
    iconCls:  'bg-emerald-500/10 text-emerald-400',
  },
  {
    k:        'ABUSEIPDB_API_KEY',
    name:     'AbuseIPDB',
    desc:     'Confidence score 0-100 cho IP đáng ngờ — dữ liệu từ cộng đồng SOC toàn cầu',
    helpUrl:  'https://www.abuseipdb.com/account/api',
    helpLabel:'Lấy free API key từ AbuseIPDB',
    Icon:     ShieldAlert,
    iconCls:  'bg-rose-500/10 text-rose-400',
  },
];

const ProviderCard = ({
  provider, current,
}: {
  provider: ProviderProps;
  current:  SettingItem | undefined;
}) => {
  const qc = useQueryClient();
  const [draft, setDraft] = useState('');

  // reset draft when provider state changes
  useEffect(() => { setDraft(''); }, [current?.value]);

  const saveM = useMutation({
    mutationFn: (v: string) => settingsApi.upsert(provider.k, v),
    onSuccess: () => {
      toast.success(`Đã lưu ${provider.name} API key`);
      qc.invalidateQueries({ queryKey: ['xdr', 'settings'] });
    },
    onError: (err) => toast.error(`${provider.name}: ${(err as Error).message}`),
  });
  const delM = useMutation({
    mutationFn: () => settingsApi.remove(provider.k),
    onSuccess: () => {
      toast.success(`Đã xoá ${provider.name} API key`);
      qc.invalidateQueries({ queryKey: ['xdr', 'settings'] });
    },
    onError: (err) => toast.error(`${provider.name}: ${(err as Error).message}`),
  });

  const configured = !!current;
  const Icon = provider.Icon;

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="flex items-center gap-3 border-b border-border bg-muted/20 p-4">
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${provider.iconCls}`}>
          <Icon size={18} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-foreground">{provider.name}</span>
            {configured ? (
              <span className="inline-flex items-center gap-1 rounded-md bg-success/10 px-1.5 py-0.5 text-[10px] font-medium text-success">
                <CheckCircle2 size={10} /> Đã cấu hình
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                <XCircle size={10} /> Chưa cấu hình
              </span>
            )}
          </div>
          <p className="text-[11px] text-muted-foreground">{provider.desc}</p>
        </div>
      </div>

      <div className="space-y-3 p-4">
        {(saveM.error || delM.error) && (
          <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <AlertCircle size={13} />
            {(saveM.error as Error)?.message || (delM.error as Error)?.message}
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-3">
          <div className="sm:col-span-2">
            <label className="mb-1.5 block text-xs font-medium text-foreground">{provider.name} API Key</label>
            <input
              type="password"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={configured ? `Hiện tại: ${current!.value}  (nhập key mới để đổi)` : 'Dán API key vào đây'}
              className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
            />
            <p className="mt-1 text-[11px] text-muted-foreground">
              {configured
                ? <>Cập nhật lần cuối: {current!.updated_at?.replace('T', ' ').slice(0, 19) ?? '—'}</>
                : <a href={provider.helpUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                    {provider.helpLabel} <ExternalLink size={11} />
                  </a>}
            </p>
          </div>

          <div className="flex flex-wrap items-end gap-2">
            <button
              onClick={() => saveM.mutate(draft)}
              disabled={!draft || saveM.isPending}
              className="flex flex-1 min-w-[100px] items-center justify-center gap-2 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saveM.isPending ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
              Lưu key
            </button>
            {configured && (
              <button
                onClick={() => delM.mutate()}
                disabled={delM.isPending}
                className="flex items-center justify-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/20 disabled:opacity-50"
                title="Xoá key"
              >
                {delM.isPending ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
              </button>
            )}
          </div>
        </div>

        <p className="text-[11px] text-muted-foreground">
          Pipeline tự động enrich mọi anomaly với 2 nguồn này (timeout 2s, cache 1 giờ). Nếu cả 2 trống, anomaly vẫn fire nhưng score chỉ tính baseline + rule weight.
        </p>
      </div>
    </div>
  );
};

const ThreatIntelIntegrations = () => {
  const settingsQ = useQuery({
    queryKey: ['xdr', 'settings'],
    queryFn:  settingsApi.list,
    refetchOnWindowFocus: false,
  });

  const items = settingsQ.data?.items ?? [];
  const byKey = new Map(items.map(i => [i.key, i]));

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <ShieldAlert size={15} className="text-primary" />
        <h3 className="text-sm font-semibold uppercase tracking-wider text-foreground">
          Tình báo mối đe dọa
        </h3>
        <span className="text-[11px] text-muted-foreground">
          Nguồn làm giàu dữ liệu cho mọi bất thường XDR
        </span>
      </div>

      {settingsQ.isLoading && items.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-6 text-center text-xs text-muted-foreground">
          Đang tải cấu hình…
        </div>
      ) : settingsQ.error ? (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          <AlertCircle size={13} />
          {(settingsQ.error as Error).message}
        </div>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {PROVIDERS.map(p => (
            <ProviderCard key={p.k} provider={p} current={byKey.get(p.k)} />
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatIntelIntegrations;
