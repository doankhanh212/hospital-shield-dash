# HQG Security Platform — Tài liệu Kỹ thuật

> **Hospital Shield Dash — Passive Asset Intelligence Platform**
> Cập nhật: 2026-04-21
> Mục đích: Giám sát thụ động (passive) toàn bộ tài sản mạng bệnh viện, phân loại thiết bị (IoMT/IoT/Workstation/Server/Network/Printer/IP Camera) và phát hiện rủi ro mà **không** gửi gói tin chủ động.

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Tech stack](#2-tech-stack)
3. [Cấu trúc thư mục](#3-cấu-trúc-thư-mục)
4. [Pipeline dữ liệu](#4-pipeline-dữ-liệu)
5. [Database schema](#5-database-schema)
6. [Parsers — Zeek log → DB](#6-parsers--zeek-log--db)
7. [Inference Engine](#7-inference-engine)
8. [Backend API](#8-backend-api)
9. [Frontend](#9-frontend)
10. [Authentication & RBAC](#10-authentication--rbac)
11. [Scan controller](#11-scan-controller)
12. [Asset Filtering & Pagination](#12-asset-filtering--pagination)
13. [NVD Vulnerability Integration](#13-nvd-vulnerability-integration)
14. [Demo Data Generator](#14-demo-data-generator)
15. [Cấu hình & deployment](#15-cấu-hình--deployment)
16. [Vận hành & kiểm chứng](#16-vận-hành--kiểm-chứng)
17. [Các hạn chế đã biết](#17-các-hạn-chế-đã-biết)
18. [Xu hướng phát triển: XDR và NAC](#18-xu-hướng-phát-triển-xdr-và-nac)

---

## 1. Tổng quan kiến trúc

```
┌──────────────┐    rsync/scp    ┌──────────────┐
│  Zeek sensor │ ───────────────▶│  ZEEK_LOG_DIR│
│ (VPS/sensor) │                 │  (TSV .gz)   │
└──────────────┘                 └──────┬───────┘
                                        │
                       ┌────────────────▼────────────────┐
                       │  Parsers (5 loại log)           │
                       │  conn / dns / dhcp / http / ssl │
                       └────────────────┬────────────────┘
                                        │  asyncpg COPY/INSERT
                                        ▼
                       ┌─────────────────────────────────┐
                       │  PostgreSQL 14+ (passive_asset) │
                       │  20 bảng — schema.sql bootstrap │
                       │  • assets, asset_ips, behaviors │
                       │  • fingerprints, dns/tls/http   │
                       │  • inference_results, alerts    │
                       │  • scan_jobs, users, vuln       │
                       └────────────────┬────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              ▼                         ▼                         ▼
   ┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
   │ Inference Engine │    │  FastAPI (port 3001) │    │  Scan controller │
   │  (rule-based)    │    │  /api/* endpoints    │    │  start/stop Zeek │
   └──────────────────┘    └──────────┬───────────┘    └──────────────────┘
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │  React 18 + Vite (port 8080) │
                       │  TanStack Query, Recharts    │
                       └──────────────────────────────┘
```

**Triết lý passive:** không bao giờ gửi packet đến hospital network; chỉ nghe lưu lượng đã được Zeek ghi lại, vì thiết bị y tế dễ crash khi bị scan chủ động.

---

## 2. Tech stack

### Backend (Python)
| Thành phần | Vai trò |
|---|---|
| **FastAPI** | REST framework (ASGI) |
| **uvicorn** | ASGI server, port `3001`, `--reload` cho dev |
| **asyncpg** | PostgreSQL async driver, `statement_cache_size=0` |
| **PyJWT / passlib** | JWT HS256 authentication, bcrypt password hashing (rounds=12) |
| **httpx** | Gọi NVD API v2.0 |
| **python-dotenv** | Load `.env` config |
| **PostgreSQL 14+** | Cơ sở dữ liệu, extension `pgcrypto` cho `gen_random_uuid()` |

### Frontend (TypeScript)
| Thành phần | Vai trò |
|---|---|
| **React 18** + **Vite 5** + **SWC** | UI framework, HMR dev server |
| **TanStack Query v5** | Server state management, cache, retry |
| **React Router v6** | Client-side routing |
| **Tailwind CSS** + **shadcn/ui** | Styling + Radix UI primitives |
| **Recharts** | Biểu đồ (pie, area, bar) |
| **lucide-react** | Icon system |
| **date-fns** | Xử lý thời gian |

Dev server port `8080`, proxy `/api → http://127.0.0.1:3001`.

---

## 3. Cấu trúc thư mục

```
hospital-shield-dash/
├── passive_asset_intel/         # Backend Python package
│   ├── __main__.py              # CLI entry: ingest / inference / serve
│   ├── main.py                  # Pipeline orchestrator
│   ├── schema.sql               # Single-file DB bootstrap (20 bảng)
│   ├── .env                     # Cấu hình runtime (gitignored)
│   │
│   ├── api/
│   │   ├── main.py              # FastAPI app + lifespan (pool, scan, disk mgr)
│   │   ├── deps.py              # DB connection dependency injection
│   │   ├── models.py            # Pydantic request/response schemas
│   │   └── routes/              # 12 router modules
│   │       ├── auth.py          # POST /login, GET /me, POST /users
│   │       ├── assets.py        # CRUD + server-side filter/sort/paginate
│   │       ├── stats.py         # GET /stats (KPI dashboard)
│   │       ├── network.py       # GET /connections, /behaviors
│   │       ├── topology.py      # GET /topology (VLAN-grouped graph)
│   │       ├── inference.py     # GET /inference/summary
│   │       ├── logs.py          # GET /dns, /tls, /http
│   │       ├── alerts.py        # GET/PATCH /alerts, /alerts/counts
│   │       ├── vulnerabilities.py # GET /vulnerabilities
│   │       ├── scan.py          # POST start/stop/restart, GET status
│   │       └── integrations.py  # GET/POST /integrations/nvd
│   │
│   ├── auth/
│   │   ├── jwt_handler.py       # encode_token / decode_token / verify_password
│   │   └── deps.py              # require_admin / require_analyst guards
│   │
│   ├── db/
│   │   ├── db.py                # Pool factory (standalone, outside API)
│   │   └── repository.py        # Upsert helpers (assets, IPs, behaviors, etc.)
│   │
│   ├── inference/
│   │   ├── engine.py            # run_inference() orchestrator + build_features()
│   │   ├── device_classifier.py # classify_asset() + signal_role + CPE generation
│   │   ├── identity.py          # Identity Engine — dedup & merge IP-only assets
│   │   ├── rules.py             # 12 rule sets (~180 rules, ~1500 dòng)
│   │   ├── validators.py        # Input sanitizers + identity fingerprinting
│   │   ├── mac_vendor.py        # OUI → vendor lookup + file cache
│   │   └── writer.py            # Upsert inference_results + evidence
│   │
│   ├── parsers/
│   │   ├── base_parser.py       # gzip/TSV reader, batch upsert loop
│   │   ├── conn_parser.py       # conn.log → connections + behaviors
│   │   ├── dns_parser.py        # dns.log → dns_queries
│   │   ├── dhcp_parser.py       # dhcp.log → fingerprints + hostnames
│   │   ├── http_parser.py       # http.log → http_sessions + fingerprints
│   │   └── ssl_parser.py        # ssl.log → tls_sessions + fingerprints
│   │
│   ├── services/
│   │   ├── alert_service.py     # Alert query/create/update
│   │   ├── scan_service.py      # Zeek subprocess control + state machine
│   │   ├── nvd_service.py       # NVD CVE sync via httpx
│   │   └── disk_manager.py      # Log rotation + DB record retention
│   │
│   ├── generator/               # Demo data generator (Zeek TSV mock)
│   │   ├── generator.py         # NetworkConfig → TSV files
│   │   ├── profiles.py          # Device fingerprint profiles per type
│   │   ├── models.py            # Config dataclasses
│   │   ├── tsv_writer.py        # Zeek-format TSV output
│   │   └── api_routes.py        # POST /generator/run, GET /generator/status
│   │
│   ├── utils/
│   │   ├── config.py            # Config dataclass + load_config()
│   │   └── logger.py            # JSON structured logging
│   │
│   └── scripts/                 # SQL utility scripts
│       └── cleanup_external_assets.sql
│
├── src/                         # Frontend React
│   ├── App.tsx                  # Routes + QueryClient + providers
│   ├── main.tsx                 # ReactDOM entry
│   ├── pages/
│   │   ├── DashboardPage.tsx    # KPI cards + pie chart + area chart
│   │   ├── AssetsPage.tsx       # Server-side filtered/paginated table + CRUD
│   │   ├── AssetDetailPage.tsx  # Full detail: IPs, fingerprints, inference
│   │   ├── NetworkPage.tsx      # 3 tab: connections / topology / protocols
│   │   ├── AlertsPage.tsx       # Alert table + inline status update
│   │   ├── LogsPage.tsx         # DNS + TLS + HTTP combined log view
│   │   ├── VulnerabilitiesPage.tsx # CVE list + severity cards
│   │   ├── LoginPage.tsx        # OAuth2 form login
│   │   ├── SettingsPage.tsx     # UI settings (client-side)
│   │   └── admin/
│   │       ├── AdminUsersPage.tsx
│   │       ├── AdminRolesPage.tsx
│   │       ├── AdminSystemPage.tsx    # Scan control + system metrics
│   │       ├── AdminRulesPage.tsx
│   │       ├── AdminIntegrationsPage.tsx # NVD config
│   │       └── AdminSetupWizardPage.tsx # Demo data generator wizard
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppSidebar.tsx   # 2-section sidebar (Giám sát + Quản trị)
│   │   │   └── DashboardLayout.tsx # Sidebar + outlet + header
│   │   ├── widgets/
│   │   │   ├── StatCard.tsx     # KPI card component
│   │   │   ├── PageHeader.tsx   # Title + description + actions
│   │   │   ├── SeverityBadge.tsx # Color-coded severity pill
│   │   │   ├── Skeletons.tsx    # Loading skeletons
│   │   │   └── EmptyState.tsx   # Empty data placeholder
│   │   └── ui/                  # ~55 shadcn/ui primitives
│   ├── hooks/
│   │   ├── useApi.ts            # TanStack Query hooks (useAssets, useStats...)
│   │   ├── useChartTheme.ts     # Recharts CSS variable tokens
│   │   ├── useTheme.tsx         # Dark/light theme provider
│   │   └── use-mobile.tsx       # Responsive breakpoint
│   └── lib/
│       ├── api.ts               # Fetch client + TS types + AssetFilterParams
│       ├── auth.ts              # localStorage token management
│       └── utils.ts             # Tailwind cn() helper
│
├── logs/                        # Zeek TSV log directories
├── public/                      # Static assets
├── vite.config.ts               # Dev server (8080) + API proxy
├── package.json                 # npm scripts: dev, server, build, test
├── tailwind.config.ts
├── tsconfig.json
└── playwright.config.ts         # E2E test config
```

---

## 4. Pipeline dữ liệu

### 4.1. Ingestion (Zeek → DB)

```
Zeek sensor ─▶ /opt/zeek/logs/current/*.log ─▶ rsync ─▶ logs/
                                                          │
                                                          ▼
                              python -m passive_asset_intel ingest
                                                          │
                              ┌───────────┬───────────────┼──────────────┬──────────┐
                              ▼           ▼               ▼              ▼          ▼
                        conn_parser  dns_parser     dhcp_parser   http_parser  ssl_parser
                              │           │               │              │          │
                              └───────────┴───────────────┴──────────────┴──────────┘
                                                          │
                                                          ▼
                                            base_parser._batch_upsert()
                                                          │
                                          ┌───────────────┼──────────────┐
                                          ▼               ▼              ▼
                                    upsert_assets   upsert_X        upsert_X
                                                  (behaviors,
                                                   fingerprints,
                                                   connections,...)
```

Mỗi parser có batch size mặc định **500 records**. Asset được tạo/dedup theo `mac_address`. IP-only asset (không có MAC) lưu với `mac_address = 'ip:<address>'` để vẫn vào pipeline dedup.

### 4.2. Inference (DB → classification)

Chạy độc lập sau ingestion (không phải streaming):

```bash
python -m passive_asset_intel.inference.engine
```

Engine:
1. SELECT assets có IP nằm trong `LOCAL_SUBNETS`.
2. Aggregate signal cho từng asset (behaviors, fingerprints, hostnames, DNS, TLS, HTTP).
3. Lookup MAC vendor qua OUI database (kết quả cache vào `.mac_vendor_cache.json`).
4. Gọi `classify_asset()` → kết quả `{device_type, os, vendor, confidence, evidence}`.
5. UPSERT `inference_results` + `inference_evidence`.

### 4.3. Alert generation

Hệ thống hiện có 2 nhánh sinh cảnh báo:

**Nhánh 1 — alert từ ingestion/runtime**

Sau ingestion, `scan_service.py` gọi `_generate_alerts()` với 3 rule:
1. **new_asset** — thiết bị mới phát hiện lần đầu
2. **suspicious_port** — port nguy hiểm (23/telnet, 445/SMB, 3389/RDP...)
3. **external_iot_connection** — IoT/IoMT kết nối ra ngoài LOCAL_SUBNETS

Alert nhóm này được dedup theo `(alert_type, source_ip, hour)` qua unique index `uq_alerts_dedup`.

**Nhánh 2 — alert từ NVD/CVE**

Sau khi NVD sync tạo `asset_vulnerabilities`, hệ thống có thể sinh thêm alert loại `vulnerability`:
1. map `cvss_score` → severity `Critical/High/Medium/Low`
2. tạo message dạng `CVE-XXXX (CVSS X.Y): description`
3. dedup theo `asset_id + vulnerability_id` trong `alerts.metadata`

Nhánh này được kích hoạt qua `POST /api/integrations/nvd/generate-alerts` để tách rõ bước đồng bộ CVE và bước sinh cảnh báo vận hành.

### 4.4. Frontend pull cycle

TanStack Query với `staleTime=30s`, `refetchOnWindowFocus=false`. UI gọi `/api/stats`, `/api/assets?...`, `/api/topology` etc. theo nhu cầu trang.

---

## 5. Database schema

20 bảng, single-file bootstrap: [passive_asset_intel/schema.sql](passive_asset_intel/schema.sql).

### 5.1. Bảng nền tảng (asset & danh tính)

| Bảng | Khóa chính / Unique | Cột chính | Mục đích |
|---|---|---|---|
| **assets** | `id uuid` / `mac_address` | mac_address, vendor, oui, asset_status, confidence_score, first_seen, last_seen | Một thiết bị vật lý (định danh bởi MAC, hoặc 'ip:X' khi không thấy MAC) |
| **asset_ips** | `id uuid` / `(asset_id, ip_address)` | ip_address (inet), is_primary | Một asset có thể có nhiều IP (DHCP renew) |
| **asset_hostnames** | `(asset_id, hostname)` | hostname, source | Hostname từ DHCP/DNS/NetBIOS |
| **tags** | `name` UNIQUE | name | Tag definition |
| **asset_tags** | `(asset_id, tag_id)` | — | Asset ↔ tag N:M |

### 5.2. Bảng signal (input cho inference)

| Bảng | Nguồn | Cột chính | Dedup |
|---|---|---|---|
| **behaviors** | conn.log | protocol, port, service, frequency | `(asset_id, protocol, port, service)` |
| **fingerprints** | ssl/dhcp/http | ja3, ja3s, user_agent, dhcp_vendor, os_guess | composite index trên 5 cột |
| **connections** | conn.log | src_asset_id, dst_asset_id, src/dst_ip/port, protocol, bytes, duration | `(src_ip, dst_ip, ports, protocol, minute)` |
| **dns_queries** | dns.log | query, answer, query_type, timestamp | — |
| **tls_sessions** | ssl.log | ja3, ja3s, server_name, validation_status, cert_issuer, next_protocol, sni_matches_cert, ssl_history | — |
| **http_sessions** | http.log | host, uri, user_agent, method, status_code | — |

### 5.3. Bảng inference & alert

| Bảng | Cột chính | FK |
|---|---|---|
| **inference_results** | device_type, os, os_version, cpe, confidence, method | `asset_id` UNIQUE, CASCADE |
| **inference_evidence** | evidence_type, value, weight | `inference_id` CASCADE |
| **alerts** | alert_type, severity, message, source_ip, status, metadata (jsonb) | `asset_id` SET NULL |
| **vulnerabilities** | cve_id (UNIQUE), cpe, cvss_score, severity, description | — |
| **asset_vulnerabilities** | detected_at, risk_score | `(asset_id, vulnerability_id)` CASCADE |

### 5.4. Bảng hệ thống

| Bảng | Cột chính | Mục đích |
|---|---|---|
| **scan_jobs** | status, log_dir, started_at, stopped_at, logs_processed, assets_discovered | Lịch sử ingestion job |
| **integrations** | name (UNIQUE), api_key, config (jsonb), last_sync_at | Cấu hình dịch vụ ngoài (NVD) |
| **file_offsets** | log_type, log_path, byte_offset | Resume point cho live-mode ingestion |
| **users** | username (UNIQUE), hashed_password (bcrypt), role, is_active | Tài khoản xác thực |

### 5.5. Index chiến lược

| Index | Bảng | Cột | Mục đích |
|---|---|---|---|
| `uq_connections_flow` | connections | (src_ip, dst_ip, ports, protocol, minute) | Dedup connection per minute |
| `uq_alerts_dedup` | alerts | (alert_type, source_ip, hour) | Dedup alert per hour |
| `uq_fingerprints_composite` | fingerprints | (asset_id, ja3, ja3s, ua, dhcp_vendor) | Dedup fingerprint |
| `idx_assets_last_seen` | assets | last_seen DESC | Sort active-first |
| `idx_connections_timestamp` | connections | timestamp DESC | Recent connections |
| `idx_alerts_status` | alerts | status | Filter by alert status |
| `idx_alerts_created_at` | alerts | created_at DESC | Recent alerts |
| `idx_inference_results_asset_created` | inference_results | (asset_id, created_at DESC) | Lookup per asset |
| `idx_vulnerabilities_cpe` | vulnerabilities | cpe | NVD CPE lookup |

### 5.6. Quy ước FK

- Tất cả asset-children dùng `ON DELETE CASCADE` (xóa asset → mất signal liên quan), **trừ**:
  - `alerts.asset_id` → `ON DELETE SET NULL` (giữ lịch sử cảnh báo)
  - `connections.src_asset_id / dst_asset_id` → `ON DELETE SET NULL`
- `inference_evidence.inference_id` cascade theo `inference_results`.

---

## 6. Parsers — Zeek log → DB

### 6.1. Định dạng đầu vào

Zeek xuất TSV với header `#fields` ở dòng 7. File có thể nén `.gz`. Parser dùng `gzip.open()` và `csv.reader(delimiter='\t')`.

### 6.2. Cách `base_parser` hoạt động

```python
# pseudo-code
for batch in read_log_batches(path, batch_size=500):
    records = [extract_record(line) for line in batch]
    asset_pairs = collect_unique_assets(records)         # (mac, ip) tuples
    asset_id_map = await upsert_assets(conn, asset_pairs)
    rows = enrich_with_asset_id(records, asset_id_map)
    await upsert_target_table(conn, rows)
```

Mỗi parser implement 2 method: `extract_record(row_dict)` và `target_table_upserter()`.

### 6.3. Mapping log → bảng

| Log file | Parser | Bảng đích | Signal trích xuất |
|---|---|---|---|
| `conn.log` | conn_parser | connections, behaviors | port, protocol, service, bytes, duration |
| `dns.log` | dns_parser | dns_queries | query, answer, query_type |
| `dhcp.log` | dhcp_parser | fingerprints, asset_hostnames | dhcp_vendor (option 60), hostname |
| `http.log` | http_parser | http_sessions, fingerprints | host, uri, user_agent |
| `ssl.log` | ssl_parser | tls_sessions, fingerprints | ja3, ja3s, server_name, validation_status, sni_matches_cert, cipher, next_protocol, ssl_history |

### 6.4. Cấu hình SSL Zeek nâng cao

Để có ja3/ja3s và validation metadata, sensor cần load scripts:

```zeek
@load policy/protocols/ssl/ja3
@load policy/protocols/ssl/ja3s
@load policy/protocols/ssl/validate-certs
```

Các trường `cert_chain_fps`, `validation_status`, `sni_matches_cert` đến từ `policy/protocols/ssl/cert-hash` và `validate-sni`.

---

## 7. Inference Engine

Pipeline 4 giai đoạn:

```
Fetch assets (CTE) ──▶ Identity Engine ──▶ Feature Builder ──▶ Classifier + Confidence Model
       │                      │                    │                       │
  FETCH_ASSETS_SQL     merge duplicates     build_features()     classify() → score → write
```

### 7.1. Aggregate query

`engine.py` dùng CTE + `<<= ANY($1::inet[])` cho subnet containment:

```sql
SELECT
  a.id, a.mac_address, a.vendor,
  json_agg(behaviors)        AS behaviors,
  json_agg(fingerprints)     AS fingerprints,
  json_agg(hostnames)        AS hostnames,
  json_agg(dns_queries)      AS dns_queries,
  json_agg(tls.server_name)  AS ssl_sni,
  json_agg(http.host)        AS http_hosts
FROM assets a
WHERE EXISTS (SELECT 1 FROM asset_ips ai
              WHERE ai.asset_id = a.id
                AND ai.ip_address <<= ANY($1::inet[]))
```

### 7.2. Identity Engine (deduplication)

[passive_asset_intel/inference/identity.py](passive_asset_intel/inference/identity.py) — phát hiện và merge asset trùng lặp.

**Vấn đề:** Khi thiết bị nhận IP mới qua DHCP mà không thấy MAC ở L2, parser tạo asset `ip:<addr>` mới → sinh ra duplicate.

**Giải pháp:** Tính behavioural fingerprint (SHA-256 của JA3 + base DNS domains + User-Agent), nhóm asset theo fingerprint, merge IP-only duplicate vào asset canonical.

```python
compute_identity_fingerprint(ja3_set, dns_domains, user_agents) → SHA-256 hex | None
```

**Quy tắc fingerprint:**
- Cần ≥ 2 loại signal khác nhau (JA3, DNS, UA) để tạo fingerprint
- DNS lấy base domain (2 label cuối: `update.microsoft.com` → `microsoft.com`)
- Tất cả input sorted → deterministic
- Composite string: `"ja3:hash1,hash2|dns:domain1,domain2|ua:agent1"`

**Quy tắc merge:**
- Asset có real MAC luôn là canonical
- Giữa 2 IP-only asset: asset có `first_seen` sớm hơn là canonical
- Re-parent toàn bộ child rows (asset_ips, hostnames, fingerprints, behaviors, connections, dns_queries, http_sessions, tls_sessions, alerts, inference_results + evidence) → canonical
- Xử lý conflict: skip IP/hostname đã tồn tại; delete fingerprint/behavior trùng composite key
- Mỗi merge trong 1 transaction → safe to retry
- Sau merge, engine re-fetch assets để asset canonical có signal phong phú hơn

### 7.3. Feature Builder

[passive_asset_intel/inference/engine.py](passive_asset_intel/inference/engine.py) — `build_features()` trích xuất feature từ raw SQL row:

```python
build_features(row) → dict:
  server_ports   : set[int]     # behaviors với direction='server'
  client_ports   : set[int]     # behaviors với direction='client'
  ja3_hashes     : set[str]     # fingerprints.ja3 (sanitized)
  ja3s_hashes    : set[str]     # fingerprints.ja3s (sanitized)
  user_agents    : list[str]    # fingerprints.user_agent
  dhcp_vendors   : list[str]    # fingerprints.dhcp_vendor
  dns_queries    : list[str]    # dns_queries
  ssl_sni        : list[str]    # tls.server_name
  http_hosts     : list[str]    # http.host
  hostnames      : list[str]    # asset_hostnames
  vendor         : str          # OUI vendor
```

Helper: `_json_list(raw)` parse JSON array an toàn, `_port_set(behaviors, direction)` filter theo direction.

### 7.4. Rule sets (12 nhóm, ~180 rules)

[passive_asset_intel/inference/rules.py](passive_asset_intel/inference/rules.py):

| Rule set | Match field | Match type | Số rule ≈ | Weight | Signal role |
|---|---|---|---|---|---|
| **SERVER_PORT_RULES** | port (int) | exact | 20 | 0.5–0.95 | SERVER |
| **CLIENT_PORT_RULES** | port (int) | exact | 20 | 0.4–0.55 | CLIENT |
| **DHCP_RULES** | dhcp_vendor | substring (ci) | 20 | 0.6–0.9 | NEUTRAL |
| **USER_AGENT_RULES** | user_agent | regex | 30 | 0.5–0.95 | CLIENT |
| **JA3_RULES** | ja3 | exact | 3 | 0.75–0.85 | CLIENT |
| **JA3S_RULES** | ja3s | exact | 7 | 0.65–0.85 | SERVER |
| **VENDOR_RULES** | vendor (OUI) | substring (ci) | 30 | 0.55–0.95 | NEUTRAL |
| **HOSTNAME_RULES** | hostname | regex | 20 | 0.65–0.92 | NEUTRAL |
| **DNS_RULES** | query | regex | 15 | 0.65–0.9 | CLIENT |
| **SNI_RULES** | server_name | regex | 12 | 0.75–0.9 | CLIENT |
| **HTTP_HOST_RULES** | host | regex | 5 | 0.75–0.85 | CLIENT |

Mỗi rule là dict:
```python
{
  "match_field": "ja3s",
  "match_value": "15af977ce25de452b96affa2addb1036",
  "match_type": "exact",
  "infer": {"device_type": "Server", "os": "Linux", "vendor": "nginx"},
  "weight": 0.80,
  "evidence_type": "ja3s",
}
```

### 7.5. Signal Role system

Mỗi evidence match được gán `signal_role` ∈ {`CLIENT`, `SERVER`, `NEUTRAL`}:

| Signal source | Role | Lý do |
|---|---|---|
| Server ports, JA3S | `SERVER` | Thiết bị đang lắng nghe / phục vụ |
| Client ports, JA3, UA, DNS, SNI, HTTP | `CLIENT` | Thiết bị đang kết nối đi |
| Vendor (OUI), DHCP, Hostname | `NEUTRAL` | Không liên quan đến hướng traffic |

**Signal role dùng cho:**
1. **Role diversity bonus**: device_type có evidence từ ≥ 2 role khác nhau → bonus `1 + 0.10 × (n_roles − 1)`, cap 1.30
2. **Cross-role conflict penalty**: khi cả CLIENT + SERVER đều vote cho cùng 1 device_type **không phải** "Network" → nhân 0.80 (vì Server thực tế ít khi đồng thời là Workstation)
3. **Dual-role device types**: `frozenset({"Network"})` — được miễn cross-role penalty

### 7.6. Classifier algorithm

`device_classifier.py` — `classify()`:

```
# Phase 1: Collect evidence with signal roles
for each rule_set (12):
  signal_role = role_map[rule_set]   # SERVER / CLIENT / NEUTRAL
  for each rule in rule_set:
    if asset.signal_field matches rule.match_value:
      matches.append({
        device_type, os, vendor, weight,
        evidence_type, evidence_value, signal_role
      })

# Phase 2: Score each device_type
for each device_type in matches:
  raw_score  = sum(m.weight for m in device_type_matches)
  roles      = set(m.signal_role for m in device_type_matches)
  n_types    = count(distinct evidence_type)

  # Multi-type bonus (cũ): +0.15 per extra evidence_type
  multi_bonus = 1 + 0.15 × (n_types − 1)

  # Role diversity bonus (mới): +0.10 per extra role
  role_bonus = min(1 + 0.10 × (len(roles) − 1), 1.30)

  # Cross-role conflict penalty
  if {CLIENT, SERVER} ⊆ roles AND device_type ∉ DUAL_ROLE_DEVICE_TYPES:
    cross_penalty = 0.80
  else:
    cross_penalty = 1.0

  final_score = raw_score × multi_bonus × role_bonus × cross_penalty

# Phase 3: Winner selection
device_type = argmax(final_score)
os          = argmax(sum(m.weight) by m.os)
vendor      = argmax(m.weight)
confidence  = round(min(final_score / MAX_THEORETICAL_SCORE, 1.0) × 100, 1)
method      = "+".join(sorted(set(m.evidence_type)))
```

**Hằng số quan trọng:**

| Constant | Value | Mô tả |
|---|---|---|
| `MAX_THEORETICAL_SCORE` | 3.0 | Điểm tối đa lý thuyết |
| `MULTI_TYPE_BONUS_PER_EXTRA` | 0.15 | Bonus per thêm 1 evidence type |
| `CONFLICT_RATIO` | 0.80 | Ngưỡng runner-up/winner → cảnh báo |
| `CONFLICT_PENALTY` | 0.70 | Penalty khi 2 device_type xấp xỉ |
| `ROLE_DIVERSITY_BONUS` | 0.10 | Bonus per thêm 1 signal role |
| `ROLE_DIVERSITY_CAP` | 1.30 | Cap role diversity multiplier |
| `CROSS_ROLE_PENALTY` | 0.80 | Penalty khi CLIENT+SERVER vote cùng type |

**JA3S đặc biệt**: nếu asset có `ja3s` mà không khớp rule nào trong `JA3S_RULES`, vẫn thêm signal `ja3s_presence` weight 0.45 → suy ra đã serve TLS → khả năng là Server.

### 7.7. Dải confidence

| Khoảng | Diễn giải | Hành động |
|---|---|---|
| 85–100% | Nhiều signal mạnh, multi-role đồng thuận | Tin được |
| 60–84% | Ít signal hoặc weight trung bình | Cross-check |
| 30–59% | Signal yếu hoặc cross-role conflict | Đánh dấu cần verify |
| < 30% | Hầu như không có signal | "Unknown", chờ thêm dữ liệu |

### 7.8. CPE generation

`_generate_cpe()` build CPE 2.3: `cpe:2.3:o:vendor:os:version:*:*:*:*:*:*:*` → cross-check NVD CVE.

---

## 8. Backend API

Base URL: `http://localhost:3001/api`. Toàn bộ route bảo vệ bằng JWT (trừ `/auth/login`, `/health`).

### 8.1. Endpoint reference

| Method | Path | Mô tả | Role |
|---|---|---|---|
| GET | `/health` | Health probe — DB latency, Zeek status, asset count | public |
| POST | `/auth/login` | Login (OAuth2 form) → JWT | public |
| GET | `/auth/me` | Thông tin user hiện tại | analyst+ |
| POST | `/auth/users` | Tạo user mới | admin |
| GET | `/assets` | List asset — server-side filter/sort/paginate | analyst+ |
| GET | `/assets/{id}` | Chi tiết asset (IPs, hostnames, behaviors, fingerprints, inference) | analyst+ |
| POST | `/assets` | Tạo asset thủ công | admin |
| PUT | `/assets/{id}` | Update asset | admin |
| DELETE | `/assets/{id}` | Xóa asset + cascade | admin |
| GET | `/stats` | KPI dashboard (assets, connections, DNS/TLS/HTTP counts, traffic) | analyst+ |
| GET | `/connections` | Connection flows (max 1000) | analyst+ |
| GET | `/behaviors` | Top port/protocol | analyst+ |
| GET | `/topology` | VLAN-grouped nodes + edges | analyst+ |
| GET | `/dns` | DNS log (max 200) | analyst+ |
| GET | `/tls` | TLS session (max 200) | analyst+ |
| GET | `/http` | HTTP session (max 200) | analyst+ |
| GET | `/inference/summary` | Tổng hợp device_type count + avg confidence | analyst+ |
| GET | `/alerts` | List alert — filter by status/severity/type | analyst+ |
| PATCH | `/alerts/{id}` | Update alert status | analyst+ |
| GET | `/alerts/counts` | Tổng theo status/severity | analyst+ |
| GET | `/vulnerabilities` | List CVE — filter by severity | analyst+ |
| GET | `/vulnerabilities/{id}` | CVE detail | analyst+ |
| POST | `/scan/start` | Khởi động ingestion scan | admin |
| POST | `/scan/stop` | Dừng scan | admin |
| POST | `/scan/restart` | Restart scan | admin |
| GET | `/scan/status` | Trạng thái + metric (logs_processed, assets_discovered) | analyst+ |
| POST | `/integrations/nvd` | Lưu NVD API key + trigger background sync đầu tiên | admin |
| GET | `/integrations/nvd` | NVD config + last sync | admin |
| POST | `/integrations/nvd/sync` | Trigger NVD CVE full sync ở background | admin |
| POST | `/integrations/nvd/test` | Test nhanh NVD trên tối đa 3 CPE | admin |
| POST | `/integrations/nvd/generate-alerts` | Sinh alert `vulnerability` từ dữ liệu CVE đã link | admin |
| POST | `/generator/run` | Tạo demo Zeek TSV data | admin |
| GET | `/generator/status` | Trạng thái generator | admin |

### 8.2. Pattern xử lý lỗi

Mỗi route bọc `try/except`:
- `HTTPException(400)` cho input invalid
- `HTTPException(500, {error, type:"database"})` cho lỗi asyncpg
- `HTTPException(500, {error, type:"internal"})` cho lỗi khác
- `HTTPException` raise lại nguyên gốc để giữ status code

### 8.3. DB connection deps

`api/deps.py` — `get_conn()` mượn 1 connection từ asyncpg pool, trả về sau response. Pool tạo bởi lifespan event.

`api/main.py` lifespan:
1. `asyncpg.create_pool()` với `statement_cache_size=0`
2. Khởi tạo `ScanService` (scan subprocess controller)
3. Khởi tạo `DiskManager` (log rotation background task)
4. Shutdown: stop scan → stop disk manager → close pool

### 8.4. Health endpoint

`GET /health` trả về:
```json
{
  "status": "ok | degraded",
  "database": { "connected": true, "latency_ms": 2.5 },
  "zeek": { "running": false },
  "ingestion": { "status": "idle", "events_per_sec": 0 },
  "assets": { "total": 92, "classified": 75, "unknown": 17 }
}
```
Mỗi DB query bọc `asyncio.wait_for(timeout=3s)` — không bao giờ block API.

---

## 9. Frontend

### 9.1. Routing

`src/App.tsx` — `QueryClient` retry=1, `refetchOnWindowFocus=false`.

| Path | Component | Nhóm sidebar | Bảo vệ |
|---|---|---|---|
| `/login` | LoginPage | — | public |
| `/` | DashboardPage | Giám sát | RequireAuth |
| `/assets` | AssetsPage | Giám sát | RequireAuth |
| `/assets/:id` | AssetDetailPage | (deep link) | RequireAuth |
| `/network` | NetworkPage (Sơ đồ mạng) | Giám sát | RequireAuth |
| `/alerts` | AlertsPage | Phân tích | RequireAuth |
| `/logs` | LogsPage | Phân tích | RequireAuth |
| `/vulnerabilities` | VulnerabilitiesPage | (deep link only) | RequireAuth |
| `/settings` | SettingsPage | (footer) | RequireAuth |
| `/admin/users` | AdminUsersPage | Quản trị | RequireAuth |
| `/admin/roles` | AdminRolesPage | Quản trị | RequireAuth |
| `/admin/integrations` | AdminIntegrationsPage | Quản trị | RequireAuth |
| `/admin/system` | AdminSystemPage | Quản trị | RequireAuth |
| `/admin/rules` | AdminRulesPage | (deep link) | RequireAuth |
| `/admin/setup` | AdminSetupWizardPage | (deep link) | RequireAuth |

### 9.1.1. Cấu trúc sidebar (v2.2)

Sidebar gom các trang thành 3 nhóm chức năng rõ ràng:

- **GIÁM SÁT** — Dashboard · Tài sản · Sơ đồ mạng
- **PHÂN TÍCH** — Cảnh báo · Nhật ký
- **QUẢN TRỊ** — Người dùng · Phân quyền · Tích hợp · Cấu hình hệ thống

Lý do tái cấu trúc:

1. `"Hành vi mạng"` và `"Hành vi"` bị bỏ làm mục cấp 1. Phân bố hành vi không trả lời câu hỏi "analyst nên xem thiết bị nào trước" — nó là dữ liệu tổng hợp, không phải ưu tiên. Thông tin hành vi đã được tích hợp vào:
   - `"Sơ đồ mạng"` (`/network`) — topology + flow + protocol view (xem 9.7).
   - Asset Detail — hành vi theo cổng/dịch vụ của từng thiết bị.
2. `"Lỗ hổng"` không còn đứng riêng trong sidebar. CVE được hiển thị tại đúng nơi người dùng cần:
   - Nhúng vào trang Asset Detail (section "Lỗ hổng" với CVE ID + severity + CVSS).
   - Cấu hình nguồn dữ liệu CVE trong `Quản trị → Tích hợp → Vulnerability Sources`.
   - Trang `/vulnerabilities` vẫn tồn tại như deep link cho danh sách tổng thể.

`RequireAuth` đọc `authStorage.isLoggedIn()` từ localStorage; nếu chưa login → redirect `/login`.

### 9.2. State management

- **Server state**: TanStack Query (`useAssets`, `useStats`, `useTopology`...) trong `hooks/useApi.ts` — tất cả `staleTime=30s`.
- **Client state**: React local `useState`/`useReducer`. Không dùng Redux/Zustand.
- **Auth state**: localStorage trực tiếp (`authStorage` — token + user info).

### 9.3. Theme

`hooks/useTheme.ts` lưu `theme` (light/dark) trong localStorage, áp `class="dark"` lên `<html>`. Recharts đọc CSS variables qua `hooks/useChartTheme.ts`.

### 9.4. Trang Dashboard

- 4+ KPI stat cards: total assets, active assets, connections, DNS, TLS, bandwidth
- Biểu đồ pie phân loại thiết bị (Recharts `PieChart`)
- Biểu đồ area lưu lượng 24h (bytes in/out + connection count)
- Bảng top assets theo connection count
- Scan control (start/stop) + health status
- Dữ liệu từ `/api/stats` + `/api/inference/summary`

### 9.5. Trang Assets

**Server-side filtering** (xem [Section 12](#12-asset-filtering--pagination) chi tiết):
- Device type dropdown, status (online/offline), vendor text input, confidence range
- Debounced search (400ms) cho IP/MAC/vendor/hostname
- Server-side sort: confidence ↑↓, IP, device type
- Pagination (20 items/page) với page numbers + ellipsis

**CRUD operations**:
- Create modal: MAC, IP, vendor, hostname
- Edit modal: pre-filled form
- Delete confirmation dialog
- Color-coded device type pills (IoMT=violet, Unknown=rose, Server=cyan...)

### 9.6. Trang Asset Detail

- Full asset info: MAC, vendor, first/last seen
- Danh sách IP addresses + hostnames
- Behaviors (protocol/port/frequency)
- Fingerprints (ja3, ja3s, user_agent, dhcp_vendor)
- TLS server names
- Inference result + expandable evidence list (type, value, weight)

### 9.7. Trang Sơ đồ mạng (`/network`)

Gộp 3 góc nhìn mạng vào 1 trang duy nhất với title `"Sơ đồ mạng"`, 3 tab:

- **Graph View** *(mặc định)*: Interactive SVG topology renderer
  - Zoom/pan, wheel-to-zoom centered on cursor
  - VLAN box layout, nodes grid 14 cột × N hàng
  - Edge color theo protocol (HTTP/HTTPS=blue, DNS=green, UDP=amber, TCP=purple)
  - Hover tooltip, click node → navigate `/assets/:id`
  - VLAN sort theo node_count giảm dần
- **Flow View**: Bảng connection flows (src/dst IP, port, protocol, bytes, vendor) từ `/api/connections` (max 1000 dòng gần nhất)
- **Protocol View**: Bar chart top port/protocol + bảng tóm tắt hành vi giao thức từ `/api/behaviors`

Trang cũ `"Hành vi mạng"` đã được đổi tên thành `"Sơ đồ mạng"` và không còn là khái niệm điều hướng chính.

### 9.8. Trang Logs

- Gộp 3 nguồn (DNS/TLS/HTTP) vào 1 bảng, mỗi nguồn 200 dòng mới nhất
- Sort theo timestamp desc
- TLS rows hiển thị rich detail: SNI, version, ja3 prefix, validation_status, sni_matches_cert
- Search + filter by type

### 9.9. Trang Alerts

- Filter: status (new/investigating/resolved), severity, type
- Inline status update (dropdown thay đổi trực tiếp)
- Vietnamese labels cho alert types
- Paginated

### 9.10. Trang Vulnerabilities

- Severity summary cards (critical/high/medium/low counts)
- CVE table: CVE ID, CVSS score (color-coded), description, affected_assets

### 9.11. API Client

`src/lib/api.ts`:
- `get<T>(path, params)` / `request<T>(method, path, body)` — generic fetch wrappers
- Auto-attach `Authorization: Bearer <token>` header
- Auto-redirect to `/login` on 401
- TypeScript interfaces cho mọi response shape
- `AssetFilterParams` interface cho server-side filtering

`src/hooks/useApi.ts`:
- `useAssets(params)` — query key includes all filter params → auto-refetch on filter change
- `useCreateAsset`, `useUpdateAsset`, `useDeleteAsset` — mutations + cache invalidation

### 9.12. Mô hình rủi ro (Risk Model)

**Mục tiêu.** Thay vì chỉ hiển thị dữ liệu, hệ thống xếp hạng từng tài sản theo mức độ ưu tiên cho analyst. Câu hỏi mà trang Dashboard và Asset List phải trả lời được là: *"Analyst nên xem thiết bị nào trước?"*

**Công thức.** Mỗi tài sản có `risk_score` trong khoảng `[0, 100]`, là tổ hợp có trọng số của 4 tín hiệu độc lập:

```
risk_score = 0.30 × cve
           + 0.30 × anomaly
           + 0.25 × unknown
           + 0.15 × exposure
```

Trong đó từng thành phần cũng được chuẩn hoá về `[0, 100]`:

| Thành phần | Công thức | Nguồn dữ liệu |
|---|---|---|
| `cve`      | `min(max_cvss × 10, 100)` | `asset_vulnerabilities` join `vulnerabilities`, lấy MAX(`cvss_score`) |
| `anomaly`  | `min(30 × high_count + 10 × other_count, 100)` | `inference_anomalies` (cột `severity`) |
| `unknown`  | `100 − confidence` (confidence cap 95%) | `inference_results.confidence` |
| `exposure` | `min(open_ports × 10, 100)` | `DISTINCT port` từ `behaviors` của asset |

**Mức rủi ro.**

| Mức | Khoảng | Màu | Ý nghĩa |
|---|---|---|---|
| `high`   | ≥ 66 | rose-500 | Cần xử lý trước trong ca |
| `medium` | 33–65 | amber-500 | Theo dõi, chưa khẩn |
| `low`    | < 33 | emerald-500 | Không có tín hiệu đáng chú ý |

**Nguyên nhân chính (reason).** Driver nào có `weight × component` cao nhất sẽ là nhãn lý do (CVE / Anomaly / Unknown / Exposure). Nếu tất cả driver đều < 5 → nhãn `Clean` ("An toàn").

**Triển khai.**
- Backend (`GET /api/assets`) trả về raw signals cho từng asset: `anomaly_count`, `anomaly_high`, `vuln_count`, `max_cvss`, `open_ports` (xem CTE `asset_details` trong `passive_asset_intel/api/routes/assets.py`).
- Frontend util: `src/lib/risk.ts` — `computeRisk()`, `riskLevelClasses()`, `riskReasonLabel()`.
- Hiển thị:
  - **Dashboard** — section "Top Risk Assets": lấy 50 asset có confidence thấp nhất, re-rank tại client theo `risk_score`, hiển thị top 8 với IP · device_type · điểm · reason · CVE · Anomaly · Tin cậy.
  - **Assets list** — cột "Rủi ro" pill (score + level), title = nhãn reason.
  - **Asset Detail** — card "Rủi ro tổng hợp" ở đầu trang với điểm tổng + 4 ô driver (CVE / Anomaly / Unknown / Exposure) kèm hint ngắn về nguồn.

**Vì sao chọn các trọng số này.** CVE là ground-truth công khai (advisory + CVSS) nên có trọng số cao nhất cùng với Anomaly — tín hiệu phát hiện lệch baseline theo thời gian thực. Unknown đứng thứ ba vì thiết bị không phân loại trên mạng bệnh viện là rủi ro tiềm tàng nhưng không chắc chắn. Exposure (số cổng mở) là nhân tố khuếch đại: một thiết bị mở nhiều cổng + có CVE nghiêm trọng đáng lo hơn thiết bị có cùng CVE nhưng đóng cổng.

### 9.13. Trang Asset Detail — section "Lỗ hổng"

Asset Detail có thêm section **"Lỗ hổng"** hiển thị CVE match với CPE suy luận của thiết bị:

- Bảng các cột: `CVE ID` (mono, primary color), `Severity` pill (critical=rose, high=orange, medium=amber, low=blue), `CVSS` score với màu theo ngưỡng (≥9=rose, ≥7=orange, ≥4=amber, <4=blue), `Mô tả`, `Ngày phát hiện`.
- Trống → gợi ý cấu hình NVD tại `Quản trị → Tích hợp → Vulnerability Sources`.
- Nguồn dữ liệu: JSON aggregation trong `GET /api/assets/{id}`, join `asset_vulnerabilities` + `vulnerabilities`, sort theo `cvss_score DESC NULLS LAST`.

### 9.14. Tích hợp — "Vulnerability Sources"

Trang `Quản trị → Tích hợp` có một nhóm riêng cho nguồn CVE:

- Section header: **"Vulnerability Sources"** (icon Bug)
- Card hiện tại: **NVD (National Vulnerability Database)**
  - Input: NVD API Key (lưu qua `POST /api/integrations/nvd`)
  - Trạng thái kết nối (Đã cấu hình / Chưa cấu hình)
  - Thời gian đồng bộ gần nhất (`last_sync_at`)
  - Nút **Lưu key** + **Đồng bộ** (`POST /api/integrations/nvd/sync`)
- Kiến trúc này để sẵn cho nguồn CVE thứ 2 (ví dụ GitHub Advisory DB, vendor feed) — chỉ cần thêm card mới vào cùng nhóm.

---

## 10. Authentication & RBAC

### 10.1. Flow

```
Frontend                           Backend
   │                                  │
   │  POST /api/auth/login            │
   │  (x-www-form-urlencoded)         │
   │  username=...&password=...       │
   ├─────────────────────────────────▶│
   │                                  │ bcrypt.verify(password, hash)
   │                                  │ jwt.encode({sub, role}, SECRET, HS256)
   │  { access_token, role }          │
   │◀─────────────────────────────────┤
   │                                  │
   │ localStorage.setItem('token')    │
   │                                  │
   │  GET /api/assets                 │
   │  Authorization: Bearer <jwt>     │
   ├─────────────────────────────────▶│
   │                                  │ require_analyst → decode JWT
   │                                  │ → check role
   │  { items, total }                │
   │◀─────────────────────────────────┤
```

Login dùng `OAuth2PasswordRequestForm` (form-encoded) để Swagger UI "Authorize" hoạt động.

### 10.2. Roles

| Role | Quyền |
|---|---|
| **admin** | Toàn quyền: CRUD user, CRUD asset, control scan, sửa rule, NVD sync |
| **analyst** | Đọc tất cả + update alert status |
| **viewer** | (Định nghĩa nhưng chưa enforce) |

`auth/deps.py`: `require_admin`, `require_analyst` raise 401/403.

### 10.3. JWT config

Env: `JWT_SECRET_KEY`, `JWT_ALG=HS256`, `JWT_EXP_HOURS=24`. Token không refresh — hết hạn user phải login lại.

### 10.4. Password hashing

`passlib.CryptContext(schemes=["bcrypt"], rounds=12)`. Schema seed user: admin / bcrypt hash.

---

## 11. Scan controller

`services/scan_service.py` quản lý subprocess Zeek/ingestion qua 2 mode:

- **file mode** — đọc batch từ thư mục log đã có (`SCAN_MODE=file`)
- **live mode** — bind interface NIC (`SCAN_MODE=live`, `ZEEK_INTERFACE=eth0`)

State machine:
```
idle ──start──▶ starting ──▶ running ──stop──▶ stopping ──▶ idle
                  │                                │
                  └──fail──▶ failed ◀──────────────┘
```

Metrics tracked: `logs_processed`, `assets_discovered`, `ingestion_rate`.

Post-ingestion hook: `_generate_alerts()` → 3 alert rules (new_asset, suspicious_port, external_iot_connection).

Trang `AdminSystemPage` section "Kiểm soát quét": hiển thị status, metrics, Start/Stop buttons.

---

## 12. Asset Filtering & Pagination

### 12.1. Backend (GET /api/assets)

Server-side filtering hoàn toàn — client không filter hay sort. CTE `asset_data` join 4 bảng:
```sql
WITH asset_data AS (
    SELECT DISTINCT ON (a.id)
        a.id, a.mac_address, a.vendor, a.first_seen, a.last_seen,
        host(ai.ip_address)::text AS ip,
        ah.hostname,
        COALESCE(ir.device_type, 'Unknown') AS device_type,
        ir.confidence, ir.os, ir.os_version, ir.cpe, ir.method
    FROM assets a
    LEFT JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary = true
    LEFT JOIN asset_hostnames ah ON ah.asset_id = a.id
    LEFT JOIN inference_results ir ON ir.asset_id = a.id
    WHERE ai.ip_address <<= ANY($1::inet[])
    ORDER BY a.id
)
SELECT ... FROM asset_data ad
WHERE <dynamic filters>
ORDER BY <sort>
LIMIT $N OFFSET $M
```

**Query params:**

| Param | Type | Mô tả |
|---|---|---|
| `limit` | int (1–5000) | Page size, default 20 |
| `offset` | int (≥0) | Pagination offset |
| `sort` | enum | `confidence_desc` (default), `confidence_asc`, `last_seen`, `ip`, `device_type` |
| `device_type` | string | Exact match: IoMT, IoT, Server, Workstation, Network, Printer, IP Camera, Unknown |
| `search` | string | ILIKE `%search%` trên IP, MAC, vendor, hostname |
| `status` | string | `online` (last_seen > 5 min) hoặc `offline` |
| `vendor` | string | ILIKE `%vendor%` partial match |
| `min_confidence` | float | Confidence ≥ value (0–100) |
| `max_confidence` | float | Confidence ≤ value (0–100) |

**Response:**
```json
{
  "items": [
    {
      "id": "uuid",
      "mac": "00:11:22:33:44:55",
      "vendor": "Cisco",
      "ip": "10.0.1.5",
      "hostname": "switch-core",
      "device_type": "Network",
      "deviceType": "Network",
      "os": "IOS",
      "confidence": 92.5,
      "protocols": ["tcp", "udp"],
      "ports": [22, 443, 80],
      "connection_count": 1500,
      "status": "online",
      "first_seen": "2026-04-10T...",
      "last_seen": "2026-04-16T..."
    }
  ],
  "total": 92
}
```

### 12.2. Frontend (AssetsPage.tsx)

Filter state quản lý bởi `useState`:
- `search` + `debouncedSearch` (400ms debounce via `useEffect`)
- `deviceTypeFilter` — dropdown từ danh sách cứng
- `statusFilter` — dropdown (Tất cả / online / offline)
- `vendorFilter` + `debouncedVendor` (400ms debounce)
- `confidenceRangeIdx` — 4 preset: Tất cả, Cao (≥80%), Trung bình (40–79%), Thấp (<40%)
- `sortKey` — 4 option: confidence ↑↓, IP, device type

Khi bất kỳ filter thay đổi → `setPage(1)` → TanStack Query tự refetch vì `queryKey` chứa `params`.

```typescript
const apiParams = {
  limit: PAGE_SIZE,
  offset: (page - 1) * PAGE_SIZE,
  sort: sortKey,
  ...(debouncedSearch ? { search: debouncedSearch } : {}),
  ...(deviceTypeFilter !== 'Tất cả' ? { device_type: deviceTypeFilter } : {}),
  ...(statusFilter !== 'Tất cả' ? { status: statusFilter } : {}),
  ...(debouncedVendor !== 'Tất cả' ? { vendor: debouncedVendor } : {}),
  ...(confidenceRangeIdx !== 0 ? { min_confidence, max_confidence } : {}),
};
const { data, isLoading } = useAssets(apiParams);
```

---

## 13. NVD Vulnerability Integration

### 13.1. Flow

```
inference_results.cpe ──▶ NVD API v2.0 ──▶ CVE matches
                                               │
                              ┌────────────────┴────────────────┐
                              ▼                                 ▼
                   UPSERT vulnerabilities             UPSERT asset_vulnerabilities
                                                                  │
                                                                  ▼
                                          POST /api/integrations/nvd/generate-alerts
                                                                  │
                                                                  ▼
                                                alerts (alert_type='vulnerability')
```

### 13.2. Service

`services/nvd_service.py`:
- Gọi `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...`
- API key lưu trong `integrations` table (name=`nvd`)
- Parse CVSS v3.1 score + severity + description
- Upsert vào `vulnerabilities` (dedup bởi `cve_id`)
- Link asset ↔ vulnerability qua `asset_vulnerabilities`
- Full sync chạy ở background task để tránh block UI
- Có test mode sync đồng bộ, giới hạn 3 CPE và timeout 90s
- Có endpoint riêng để generate `vulnerability alerts` từ dữ liệu CVE đã link

### 13.3. API Endpoints

- `POST /api/integrations/nvd` — lưu API key và trigger background sync đầu tiên
- `GET /api/integrations/nvd` — trả config + last_sync_at
- `POST /api/integrations/nvd/sync` — trigger full sync ở background
- `POST /api/integrations/nvd/test` — probe nhanh tối đa 3 CPE, trả sample CVE để kiểm chứng realtime
- `POST /api/integrations/nvd/generate-alerts` — sinh cảnh báo `vulnerability` từ `asset_vulnerabilities`

### 13.4. Frontend

`AdminIntegrationsPage` hiển thị NVD API key config, runtime status cards, nút `Lưu key`, `Đồng bộ`, `Test CVE`, `Tạo cảnh báo`.
`VulnerabilitiesPage` hiển thị CVE list với severity cards.
`AlertsPage` hiển thị kết quả sau khi `generate-alerts` tạo các alert loại `vulnerability`.

---

## 14. Demo Data Generator

### 14.1. Mục đích

Tạo Zeek TSV log giả lập để demo/test mà không cần sensor thật.

### 14.2. Flow

```
Frontend (AdminSetupWizardPage)
    │
    │  POST /api/generator/run
    │  { org_name, domain, dns_server, vlans[], simulate_days, events_per_device }
    ▼
generator.py
    │
    ├── Tạo device profiles per VLAN (MAC, IP, hostname)
    ├── Simulate conn/dns/dhcp/http/ssl events
    └── Ghi TSV files vào logs/generated_YYYYMMDD_HHMMSS/
        ├── conn.log
        ├── dns.log
        ├── dhcp.log
        ├── http.log
        └── ssl.log
```

### 14.3. VLAN Configuration

```typescript
interface VlanConfig {
  vlan_id: number;
  name: string;
  subnet: string;         // e.g. "10.10.1.0/24"
  device_type: DeviceType; // IoMT | IoT | Workstation | Server | Network
  device_count: number;
}
```

### 14.4. Device Profiles

`generator/profiles.py` chứa fingerprint templates per device type:
- **IoMT**: ja3/ja3s cho HL7, DICOM; DHCP vendor class "GE Healthcare", "Philips"
- **IoT**: DNS patterns cho cloud services; user-agent "ESP8266", "Tasmota"
- **Workstation**: Windows/macOS user-agents; DNS cho update services
- **Server**: TLS server-side ja3s; high-port behaviors

---

## 15. Cấu hình & deployment

### 15.1. Environment variables

`passive_asset_intel/.env`:

| Variable | Default | Mô tả |
|---|---|---|
| `DB_HOST` | localhost | PostgreSQL host |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | passive_asset_intel | Database name |
| `DB_USER` | postgres | DB user |
| `DB_PASSWORD` | — | DB password |
| `DB_POOL_MIN` | 2 | Minimum pool connections |
| `DB_POOL_MAX` | 10 | Maximum pool connections |
| `BATCH_SIZE` | 500 | Parser batch size |
| `LOG_LEVEL` | INFO | Python logging level |
| `ZEEK_LOG_DIR` | — | Đường dẫn đến thư mục Zeek log |
| `SCAN_MODE` | file | `file` hoặc `live` |
| `ZEEK_INTERFACE` | — | NIC cho live mode |
| `LOCAL_SUBNETS` | RFC1918 | CIDR list phân biệt internal/external |
| `JWT_SECRET_KEY` | — | HMAC key cho JWT (≥32 chars) |
| `LOG_RETENTION_DAYS` | 7 | Xóa log files cũ hơn N ngày |
| `API_CORS_ORIGINS` | localhost:8080,5173 | CORS whitelist |

### 15.2. Khởi chạy development

```bash
# Một lệnh chạy cả backend + frontend
npm run dev
# → uvicorn :3001 + vite :8080 song song (via concurrently)
```

Hoặc tách riêng:
```bash
npm run server      # backend only — port 3001 (uvicorn --reload)
npm run dev:ui      # frontend only — port 8080
```

### 15.3. Bootstrap database

```bash
createdb passive_asset_intel
psql -d passive_asset_intel -f passive_asset_intel/schema.sql
```

Schema.sql tạo:
- 1 extension (pgcrypto)
- 20 bảng (IF NOT EXISTS)
- 3 unique indexes (connections dedup, alerts dedup, fingerprints composite)
- 14 performance indexes
- 1 seed user (admin)

### 15.4. Build production

```bash
npm run build     # → dist/ static files (Vite)
# Deploy: serve dist/ qua nginx, proxy /api → backend uvicorn
```

Cho môi trường VPS/Docker, cách bootstrap chuẩn hiện tại là dùng `setup.sh` thay vì build tay từng service.

### 15.5. One-command VPS deployment

```bash
./setup.sh --reset
```

Script này thực hiện end-to-end:
- dọn stack cũ của project (`down -v --remove-orphans`)
- xoá volume Postgres cũ khi reset
- cleanup Docker state + builder cache của riêng project
- pre-pull base images, build lại với `--pull --no-cache`, retry 1 lần nếu build lỗi
- `up -d --force-recreate --remove-orphans`
- chờ cả API `:3001/health` và Web UI `http://localhost/` sẵn sàng
- tạo tài khoản admin
- nếu có `./logs/*.log` thì stage sang `./zeek-logs` rồi chạy ingest + inference

Mục tiêu của `setup.sh` là để operator chỉ cần 1 lệnh cho vòng đời `cleanup → rebuild → run → verify`.

### 15.6. Vite proxy config

`vite.config.ts`:
- Dev port: `8080`
- Proxy: `/api` + `/health` → `http://127.0.0.1:3001`
- Path alias: `@` → `./src`
- React SWC plugin for fast HMR

---

## 16. Vận hành & kiểm chứng

### 16.1. Kiểm tra ingestion

```sql
SELECT COUNT(*) FROM assets;
SELECT COUNT(*) FROM connections;
SELECT MAX(timestamp) FROM connections;  -- mới nhất
```

### 16.2. Phân bố device types

```sql
SELECT COALESCE(ir.device_type, 'Unknown') AS device_type, COUNT(*)
FROM assets a
LEFT JOIN inference_results ir ON ir.asset_id = a.id
GROUP BY 1 ORDER BY 2 DESC;
```

### 16.3. Re-run inference sau khi update rules

```bash
python -c "
import asyncio, os
from dotenv import load_dotenv
load_dotenv('passive_asset_intel/.env')
from passive_asset_intel.inference.engine import run_inference
dsn = f'postgresql://{os.getenv(\"DB_USER\")}:{os.getenv(\"DB_PASSWORD\")}@{os.getenv(\"DB_HOST\")}:{os.getenv(\"DB_PORT\")}/{os.getenv(\"DB_NAME\")}'
subnets = os.getenv('LOCAL_SUBNETS').split(',')
print(asyncio.run(run_inference(dsn=dsn, dry_run=False, local_subnets=subnets)))
"
```

### 16.4. Verify 1 asset cụ thể

```sql
SELECT
  a.id,
  ai.ip_address,
  ah.hostname,
  ir.device_type, ir.os, ir.confidence, ir.method,
  json_agg(json_build_object('type', ie.evidence_type, 'value', ie.value, 'weight', ie.weight))
    AS evidence
FROM assets a
LEFT JOIN asset_ips ai ON ai.asset_id = a.id AND ai.is_primary
LEFT JOIN asset_hostnames ah ON ah.asset_id = a.id
LEFT JOIN inference_results ir ON ir.asset_id = a.id
LEFT JOIN inference_evidence ie ON ie.inference_id = ir.id
WHERE ai.ip_address = '10.0.1.5'
GROUP BY a.id, ai.ip_address, ah.hostname, ir.device_type, ir.os, ir.confidence, ir.method;
```

### 16.5. Kiểm tra API filters

```bash
# Test device_type filter
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3001/api/assets?device_type=IoMT&limit=5" | jq .total

# Test search filter
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3001/api/assets?search=10.0.1&limit=5" | jq .total

# Test confidence range
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:3001/api/assets?min_confidence=80&max_confidence=100&limit=5" | jq .total
```

---

## 17. Các hạn chế đã biết

1. **JA3S không khẳng định chiều** — engine hiện coi mọi asset có `ja3s` là Server, kể cả khi đó là client kết nối tới HTTPS server. Nên tách theo Zeek `is_orig` flag.

2. **Inference không streaming** — phải chạy thủ công sau ingestion. Cần cron hoặc trigger sau mỗi batch parse.

3. **Asset dedup chỉ theo MAC** — DHCP renew hoặc MAC randomization tạo asset mới. Không có hostname-based dedup.

4. **Confidence formula** — `sum / num_signals` phạt asset có nhiều signal yếu. Asset 5 signal weight 0.5 (conf=50%) ít tin hơn asset 1 signal weight 0.95 (conf=95%).

5. **Không có audit log** — thay đổi alert status, asset CRUD không lưu vết user nào sửa.

6. **JWT không revoke được** — token compromise phải chờ hết hạn 24h.

7. **NVD sync eventual consistency** — `/integrations/nvd/sync` hiện chạy background nên UI không có progress/job tracking chi tiết; trong trường hợp sync bị gián đoạn giữa chừng, analyst có thể phải chạy lại `POST /integrations/nvd/generate-alerts` để đồng bộ phần alerts với `asset_vulnerabilities`.

8. **Frontend chưa có refresh chủ động** — `refetchOnWindowFocus=false`, dữ liệu không tự cập nhật. User phải bấm "Làm mới".

9. **No CSRF protection** — JWT trong localStorage chống CSRF nhưng dễ bị XSS đánh cắp.

10. **Rule coverage** — ~180 rules chưa phủ hết hãng thiết bị y tế Việt Nam. Cần mở rộng theo dữ liệu thực tế.

11. **Viewer role chưa enforce** — role `viewer` được định nghĩa nhưng backend chưa phân biệt với analyst.

---

## 18. Xu hướng phát triển: XDR và NAC

### 18.1. Vị trí hiện tại của nền tảng

Ở trạng thái hiện tại, Hospital Shield Dash là một nền tảng **Passive Asset Intelligence + Network Detection Context**:
- có inventory tương đối đầy đủ của tài sản mạng nội bộ
- có identity/profile theo MAC, IP, hostname, JA3/JA3S, DNS, HTTP, DHCP
- có inference để phân loại thiết bị và gán confidence
- có alert runtime và alert từ CVE/NVD

Đây là nền tảng dữ liệu rất phù hợp để phát triển lên 2 hướng lớn hơn:
1. **XDR** — mở rộng từ quan sát mạng sang tương quan đa nguồn và response.
2. **NAC** — mở rộng từ nhận diện thụ động sang policy kiểm soát truy cập mạng.

Điểm quan trọng: với môi trường bệnh viện, hướng đi nên là **passive-first, recommendation-first** trước khi tiến tới enforcement tự động.

### 18.2. Xu hướng phát triển theo hướng XDR

**XDR (Extended Detection and Response)** là bước phát triển tự nhiên khi hệ thống không chỉ trả lời câu hỏi "thiết bị nào đang tồn tại" mà còn trả lời thêm:
- thiết bị đó liên quan đến user nào
- đang phát sinh hành vi gì bất thường trên nhiều lớp
- cùng một sự kiện có xuất hiện trên endpoint, identity, firewall, email hay cloud không
- nên phản ứng thế nào và ai phải phê duyệt

Với codebase hiện tại, nền tảng có thể đóng vai trò **network-native telemetry layer** cho XDR. Các bước mở rộng hợp lý:

1. **Chuẩn hoá multi-source telemetry**
  - ingest thêm log từ EDR, Windows Event, AD/LDAP, VPN, firewall, proxy, email gateway
  - đưa về một schema chung theo `asset`, `user`, `session`, `destination`, `indicator`

2. **Correlation engine / incident engine**
  - gom alert rời rạc thành incident theo thực thể và time window
  - map sang MITRE ATT&CK technique nếu đủ signal
  - tạo timeline: network flow → DNS → TLS → CVE → auth event → analyst action

3. **Entity graph và risk propagation**
  - nối `asset ↔ user ↔ subnet ↔ service ↔ CVE ↔ external destination`
  - khi một asset có CVE nghiêm trọng và đồng thời phát sinh kết nối đáng ngờ, risk score phải tăng theo ngữ cảnh chứ không chỉ theo từng tín hiệu riêng lẻ

4. **Response workflow**
  - giai đoạn đầu: chỉ đưa ra khuyến nghị xử lý
  - giai đoạn sau: playbook bán tự động như mở ticket, gắn tag, gọi webhook, push SIEM/SOAR

**Khuyến nghị kiến trúc cho XDR:**
- tách event ingestion khỏi request/response API bằng queue hoặc background workers
- bổ sung bảng `incidents`, `incident_entities`, `alert_history`, `response_actions`
- thêm audit trail đầy đủ cho analyst workflow
- thêm rule engine có versioning và test fixtures

### 18.3. Xu hướng phát triển theo hướng NAC

**NAC (Network Access Control)** là lớp tiếp theo sau asset visibility. Nếu XDR tập trung vào detection/response đa nguồn, thì NAC tập trung vào câu hỏi:
"Thiết bị này có nên được vào mạng nào, với mức truy cập nào, và khi rủi ro tăng thì có cần cô lập hay không?"

Trong bối cảnh bệnh viện, NAC không nên triển khai theo kiểu chặn mạnh ngay từ đầu. Lộ trình an toàn hơn:

1. **Discovery mode**
  - chỉ quan sát, profile và phân nhóm thiết bị
  - gợi ý chính sách VLAN/ACL nhưng chưa enforce

2. **Advisory mode**
  - sinh policy recommendation theo loại thiết bị: IoMT, Workstation, Server, Printer, Camera
  - ví dụ: máy chẩn đoán hình ảnh chỉ nên nói chuyện với PACS, HIS, domain controller, NTP, DNS

3. **Controller integration mode**
  - tích hợp với Cisco ISE, Aruba ClearPass, FortiNAC hoặc controller nội bộ
  - sử dụng RADIUS CoA, dynamic VLAN, downloadable ACL, quarantine VLAN hoặc restricted role

4. **Closed-loop enforcement mode**
  - chỉ áp dụng cho nhóm thiết bị có confidence cao và có quy trình phê duyệt
  - với IoMT/medical devices, enforcement nên có allowlist, maintenance window và rollback plan rõ ràng

**Năng lực cần bổ sung trước khi tiến lên NAC:**
- asset criticality: thiết bị nào là clinical-critical, life-support, lab, imaging, admin
- ownership/site context: thiết bị thuộc khoa nào, switch nào, VLAN nào, rack nào
- confidence threshold cho policy: chỉ enforce khi classification đủ tin cậy
- exception registry cho thiết bị legacy/fragile
- audit log để biết ai đã approve/quarantine/restore thiết bị nào

### 18.4. Lộ trình khuyến nghị cho repo này

Lộ trình thực tế, ít rủi ro vận hành nhất:

**Phase 1 — củng cố nền tảng hiện tại**
- audit log cho asset, alert, admin actions
- background job tracking cho NVD sync / ingest / inference
- incident-ready schema thay vì chỉ có alert rời rạc
- asset criticality, location, department, owner

**Phase 2 — XDR-ready**
- ingest thêm identity/auth/firewall/EDR logs
- incident correlation + timeline UI
- webhook/SIEM export + playbook actions

**Phase 3 — NAC advisory**
- policy recommendation theo device type và risk level
- simulation mode: nếu enforce thì thiết bị nào sẽ bị ảnh hưởng
- approval workflow cho isolate / restrict / restore

**Phase 4 — NAC enforcement có kiểm soát**
- tích hợp controller NAC thực tế
- apply policy theo nhóm nhỏ trước
- rollback + exception path cho IoMT quan trọng

Kết luận kỹ thuật: repo hiện tại đã là một nền tốt để đi lên **NDR-context → XDR-context → NAC advisory → NAC enforcement**, nhưng cần giữ nguyên nguyên tắc cốt lõi là **không làm gián đoạn hệ thống y tế chỉ vì một classifier hoặc một alert có confidence chưa đủ cao**.

---

**Nguồn code:**
- Backend: [passive_asset_intel/](passive_asset_intel/)
- Frontend: [src/](src/)
- Schema: [passive_asset_intel/schema.sql](passive_asset_intel/schema.sql)
- Rules: [passive_asset_intel/inference/rules.py](passive_asset_intel/inference/rules.py)
