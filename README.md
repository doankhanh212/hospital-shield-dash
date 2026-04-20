# HQG Security Platform — Hospital Shield Dash

Nền tảng giám sát an ninh mạng bệnh viện tập trung vào nhận dạng thụ động tài sản IoT/IoMT, phân tích hành vi mạng, và phân loại thiết bị tự động từ dữ liệu Zeek.

## Kiến trúc tổng quan

```
                    ┌──────────────┐
   Zeek 8.0.5       │  Zeek Logs   │   dhcp.log, conn.log, dns.log,
   (on VPS)    ───> │  (TSV files) │   http.log, ssl.log
                    └──────┬───────┘
                           │
            ┌──────────────▼───────────────┐
            │  Python Ingestion Pipeline   │  passive_asset_intel/
            │  (asyncpg, batch upsert)     │  parsers/ → db/repository.py
            └──────────────┬───────────────┘
                           │
            ┌──────────────▼───────────────┐
            │  Inference Engine            │  passive_asset_intel/inference/
            │  (MAC OUI + port + DHCP +    │  rules.py → device_classifier.py
            │   JA3 + User-Agent)          │  → writer.py
            └──────────────┬───────────────┘
                           │
            ┌──────────────▼───────────────┐
            │  PostgreSQL 16+              │  15 tables, UPSERT with
            │  Database: passive_asset_intel│  unique indexes
            └──────────────┬───────────────┘
                           │
            ┌──────────────▼───────────────┐
            │  Express.js API Server       │  server/api.js
            │  Port 3001 — 9 REST endpoints│  (Node.js, pg driver)
            └──────────────┬───────────────┘
                           │
            ┌──────────────▼───────────────┐
            │  React 18 Dashboard          │  src/
            │  Vite + Tailwind + shadcn/ui │  TanStack Query → API hooks
            │  Port 8080                   │  Recharts visualizations
            └──────────────────────────────┘
```

---

## Khởi chạy nhanh

### Yêu cầu

- Node.js 18+
- Python 3.10+ (khuyến nghị 3.12+)
- PostgreSQL 16+
- Zeek 8.x log files (TSV format)

### 1. Cài đặt dependencies

```bash
# Frontend + API server
npm install

# Python pipeline
cd passive_asset_intel
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows
# source .venv/bin/activate          # Linux/Mac
pip install -r requirements.txt
```

### 2. Chuẩn bị PostgreSQL

```bash
# Tạo database
createdb passive_asset_intel

# Nạp schema appliance
psql -d passive_asset_intel -f passive_asset_intel/schema.sql
```

### 3. Cấu hình .env

File `passive_asset_intel/.env`:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=passive_asset_intel
DB_USER=postgres
DB_PASSWORD=your_password
DB_POOL_MIN=2
DB_POOL_MAX=10
BATCH_SIZE=500
LOG_LEVEL=INFO
ZEEK_LOG_DIR=c:/path/to/your/zeek/logs
SCAN_MODE=file
ZEEK_INTERFACE=eth0
ZEEK_LOG_PATH=/tmp/zeek-live
ZEEK_LOAD_PACKAGES=false
ZEEK_EXTRA_ARGS=
```

Để bật JA3/JA3S cho **live mode**, Zeek cần nạp thêm package/script JA3 vì `ssl.log`
không có `ja3` và `ja3s` theo mặc định.

Khuyến nghị với `zkg`:

```bash
zkg install ja3
zkg load ja3
```

Sau đó bật trong `.env`:

```env
SCAN_MODE=live
ZEEK_INTERFACE=eth0
ZEEK_LOAD_PACKAGES=true
```

Khi `zkg` có mặt, live mode sẽ tự đọc `zkg config script_dir` và `plugin_dir`
để bổ sung `ZEEKPATH` / `ZEEK_PLUGIN_PATH`, rồi chạy Zeek với `packages`.

Nếu không dùng `zkg`, có thể nạp trực tiếp script JA3 bằng `ZEEK_EXTRA_ARGS`, ví dụ:

```env
ZEEK_EXTRA_ARGS=/opt/zeek/share/zeek/site/packages/ja3/__load__.zeek
```

### 4. Ingest dữ liệu Zeek

```bash
# Ingest toàn bộ log types (dhcp → conn → dns → http → ssl)
python -m passive_asset_intel ingest

# Chạy inference phân loại thiết bị
python -m passive_asset_intel infer

# Hoặc chạy cả 2 liên tiếp
python -m passive_asset_intel run-all
```

### 5. Khởi chạy ứng dụng

```bash
npm run dev
```

Lệnh này chạy đồng thời:
- **[API]** Express server tại `http://localhost:3001`
- **[UI]** Vite dev server tại `http://localhost:8080`

Mở trình duyệt tại `http://localhost:8080`.

---

## Cấu trúc thư mục

```
hospital-shield-dash/
├── src/                              # Frontend React application
│   ├── App.tsx                       # Router + providers
│   ├── main.tsx                      # React entry point
│   ├── index.css                     # Global CSS + Tailwind
│   ├── pages/                        # Route pages (15 trang)
│   │   ├── DashboardPage.tsx         # Tổng quan KPI, biểu đồ
│   │   ├── AssetsPage.tsx            # Danh sách 4,640+ tài sản
│   │   ├── AssetDetailPage.tsx       # Chi tiết: IP, fingerprint, behaviors, inference
│   │   ├── NetworkPage.tsx           # Luồng kết nối, top port, giao thức
│   │   ├── LogsPage.tsx              # DNS + TLS + HTTP logs hợp nhất
│   │   ├── AlertsPage.tsx            # Quản lý cảnh báo
│   │   ├── VulnerabilitiesPage.tsx   # CVE tracking
│   │   ├── SettingsPage.tsx          # Cài đặt cá nhân
│   │   └── admin/                    # 5 trang quản trị
│   │       ├── AdminIntegrationsPage.tsx  # Trạng thái Zeek, PG, Syslog...
│   │       ├── AdminSystemPage.tsx        # Cấu hình hệ thống
│   │       ├── AdminUsersPage.tsx         # Quản lý user
│   │       ├── AdminRolesPage.tsx         # Ma trận phân quyền
│   │       └── AdminRulesPage.tsx         # Detection rules
│   ├── components/
│   │   ├── layout/                   # DashboardLayout, AppSidebar
│   │   ├── ui/                       # 52 shadcn/ui components
│   │   └── widgets/                  # StatCard, PageHeader, Skeletons...
│   ├── hooks/
│   │   ├── useApi.ts                 # TanStack Query hooks (9 hooks)
│   │   ├── useTheme.tsx              # Dark/light mode provider
│   │   └── useChartTheme.ts          # Recharts color palette
│   ├── lib/
│   │   ├── api.ts                    # API client + TypeScript interfaces
│   │   └── utils.ts                  # Utilities
│   └── data/
│       └── mockData.ts              # Legacy mock data (không còn sử dụng)
│
├── server/                           # Express.js API backend
│   └── api.js                        # 9 REST endpoints, pg driver
│
├── passive_asset_intel/              # Python pipeline
│   ├── main.py                       # CLI: ingest / infer / run-all
│   ├── __main__.py                   # Module runner
│   ├── .env                          # Database + pipeline config
│   ├── requirements.txt              # asyncpg, python-dotenv, httpx
│   ├── db/
│   │   ├── db.py                     # asyncpg pool manager
│   │   └── repository.py             # Tất cả upsert/write operations
│   ├── parsers/
│   │   ├── base_parser.py            # Abstract TSV parser (Zeek 8 format)
│   │   ├── dhcp_parser.py            # MAC → asset, IP, hostname, vendor
│   │   ├── conn_parser.py            # Connections, behaviors
│   │   ├── dns_parser.py             # DNS queries
│   │   ├── http_parser.py            # HTTP sessions, user-agent
│   │   └── ssl_parser.py             # TLS sessions, JA3
│   ├── inference/
│   │   ├── engine.py                 # Orchestrator: fetch → classify → write
│   │   ├── device_classifier.py      # Multi-signal classification logic
│   │   ├── rules.py                  # 50+ rule definitions (port, DHCP, UA, JA3, vendor)
│   │   ├── mac_vendor.py             # MAC OUI → vendor via macvendors.com
│   │   └── writer.py                 # UPSERT inference_results + evidence
│   └── utils/
│       ├── config.py                 # Config loader từ .env
│       └── logger.py                 # Structured JSON logging
│
├── passive_asset_intel/schema.sql    # PostgreSQL appliance bootstrap schema
├── package.json                      # npm scripts + dependencies
├── vite.config.ts                    # Vite bundler config
├── tailwind.config.ts                # Tailwind custom theme
└── tsconfig.json                     # TypeScript config
```

---

## Tech Stack chi tiết

### Frontend

| Công nghệ | Phiên bản | Vai trò |
|---|---|---|
| React | 18.3.1 | UI framework |
| TypeScript | 5.8.3 | Type safety |
| Vite | 5.4.19 | Bundler + HMR (SWC transpiler) |
| Tailwind CSS | 3.4.17 | Utility-first CSS |
| shadcn/ui | — | 52 UI components trên Radix UI primitives |
| Radix UI | latest | Accessible headless components |
| TanStack Query | 5.83.0 | Server state management, auto-refresh 30s |
| React Router | 6.30.1 | Client-side routing (15 routes) |
| Recharts | 2.15.4 | Dashboard charts (PieChart, AreaChart, BarChart) |
| Lucide React | 0.462.0 | Icon library |
| date-fns | 3.6.0 | Date formatting |
| Zod | 3.25.76 | Schema validation |
| next-themes | 0.3.0 | Dark/light mode toggle |

### Backend API

| Công nghệ | Phiên bản | Vai trò |
|---|---|---|
| Express.js | 5.2.1 | REST API framework |
| pg (node-postgres) | 8.20.0 | PostgreSQL driver |
| cors | 2.8.6 | Cross-origin cho frontend |
| concurrently | 9.2.1 | Chạy song song API + Vite |

### Python Pipeline

| Công nghệ | Phiên bản | Vai trò |
|---|---|---|
| Python | 3.10+ | Runtime |
| asyncpg | 0.31.0 | Async PostgreSQL driver + connection pool |
| python-dotenv | 1.0.1 | Config từ .env |
| httpx | 0.27.0+ | Async HTTP client (MAC vendor API) |

### Database

| Công nghệ | Phiên bản | Vai trò |
|---|---|---|
| PostgreSQL | 16+ | RDBMS chính |

### Testing & Tooling

| Công nghệ | Vai trò |
|---|---|
| Vitest | Unit testing |
| Testing Library | React component testing |
| Playwright | E2E testing (scaffold) |
| ESLint | Linting |

---

## API Endpoints

Base URL: `http://localhost:3001/api`

| Method | Endpoint | Mô tả | Params |
|---|---|---|---|
| GET | `/assets` | Danh sách tài sản + inference | `limit`, `offset` |
| GET | `/assets/:id` | Chi tiết tài sản (IPs, behaviors, fingerprints, inference, evidence) | — |
| GET | `/stats` | KPI tổng hợp cho Dashboard | — |
| GET | `/connections` | Luồng kết nối mạng | `limit` |
| GET | `/dns` | Truy vấn DNS | `limit` |
| GET | `/tls` | Phiên TLS/SSL | `limit` |
| GET | `/http` | Phiên HTTP | `limit` |
| GET | `/behaviors` | Tóm tắt giao thức/port | — |
| GET | `/inference/summary` | Phân bổ device_type | — |

### Ví dụ response `/api/stats`

```json
{
  "assets": { "total": "4640", "active": "82", "ip_only": "4558", "has_mac": "82" },
  "connections": { "total": "38186", "total_bytes_sent": "58369658", "total_bytes_recv": "1018905986" },
  "dns": { "total": "3090", "unique_assets": "95" },
  "tls": { "total": "10984", "unique_assets": "2488" },
  "http": { "total": "5045", "unique_assets": "98" },
  "topProtocols": [{ "protocol": "tcp", "count": "6990" }, ...],
  "topAssets": [{ "id": "...", "ip": "45.142.193.161", "conn_count": "8588" }, ...],
  "trafficByHour": [{ "hour": "2026-04-08T19:00:00.000Z", "bytes_out": "7628766", "conn_count": "842" }, ...]
}
```

---

## Database Schema

### 15 tables

```
assets ─────────────┬── asset_ips
                    ├── asset_hostnames
                    ├── fingerprints (ja3, ja3s, user_agent, dhcp_vendor)
                    ├── behaviors (protocol, port, service, frequency)
                    ├── connections (src ←→ dst, bytes, duration)
                    ├── dns_queries
                    ├── tls_sessions
                    ├── http_sessions
                    ├── inference_results ── inference_evidence
                    ├── asset_vulnerabilities ── vulnerabilities
                    └── asset_tags ── tags
```

### Bảng chính

| Table | Mô tả | Records (example) |
|---|---|---|
| `assets` | Tài sản mạng, nhận dạng bằng MAC | 4,640 |
| `asset_ips` | Lịch sử IP assignment | — |
| `connections` | Kết nối mạng (src → dst) | 38,186 |
| `behaviors` | Protocol/port patterns + frequency | 7,413 |
| `dns_queries` | DNS lookup logs | 3,090 |
| `tls_sessions` | TLS handshake + certificates | 10,984 |
| `http_sessions` | HTTP request/response | 5,045 |
| `fingerprints` | JA3, User-Agent, DHCP vendor | — |
| `inference_results` | Kết quả phân loại (device_type, os, cpe) | 4,640 |
| `inference_evidence` | Bằng chứng cho mỗi inference | — |

### Unique indexes (cho UPSERT)

```sql
-- asset_ips: tránh duplicate IP per asset
CREATE UNIQUE INDEX uq_asset_ips_asset_ip ON asset_ips(asset_id, ip_address);

-- behaviors: aggregate frequency per protocol/port
CREATE UNIQUE INDEX uq_behaviors_asset_proto_port_svc ON behaviors(asset_id, protocol, port, service);

-- asset_hostnames: one record per hostname per asset
CREATE UNIQUE INDEX uq_asset_hostnames_asset_host ON asset_hostnames(asset_id, hostname);

-- fingerprints: COALESCE expression index for nullable columns
CREATE UNIQUE INDEX uq_fingerprints_composite ON fingerprints(
  asset_id, COALESCE(ja3,''), COALESCE(ja3s,''), COALESCE(user_agent,''), COALESCE(dhcp_vendor,'')
);

-- inference_results: one result per asset
ALTER TABLE inference_results ADD CONSTRAINT uq_inference_results_asset UNIQUE (asset_id);
```

---

## Python Pipeline chi tiết

### Zeek Log Parser (TSV Format)

Zeek 8.0.5 xuất log dạng **TSV** (tab-separated), không phải JSON. File bắt đầu bằng header:

```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#fields ts      uid     id.orig_h       id.orig_p       ...
#types  time    string  addr            port            ...
```

`BaseParser` đọc `#fields` để xây dựng column names dynamically, xử lý `-` (unset) và `(empty)`.

### Ingestion Flow

```
Zeek TSV file
  → BaseParser.ingest() — stream từng dòng, gom batch
    → DhcpParser.process_batch() — MAC-first, upsert asset
    → ConnParser.process_batch() — src/dst asset, connection, behavior
    → DnsParser.process_batch() — DNS query records
    → HttpParser.process_batch() — HTTP sessions + user-agent fingerprint
    → SslParser.process_batch() — TLS sessions + JA3 fingerprint (nếu Zeek đã nạp JA3 package/script)
      → Repository.upsert_*() — asyncpg batch transactions
```

**Thứ tự quan trọng**: DHCP chạy trước để có MAC address. Các parser sau dùng MAC (nếu có) hoặc fallback sang synthetic `ip:<addr>`.

### Inference Engine

```
engine.py
  → Fetch ALL assets + behaviors + fingerprints (1 query, json_agg)
  → For each asset:
      1. mac_vendor.py   — MAC OUI → vendor string (macvendors.com API, cached, rate-limited)
      2. device_classifier.py — Apply ALL rules from rules.py
         ├── PORT_RULES:      port 104 → DICOM → IoMT (weight 0.9)
         ├── DHCP_RULES:      "MSFT" → Windows (weight 0.85)
         ├── USER_AGENT_RULES: "GE.?MRI" → IoMT + GE Healthcare (weight 0.95)
         ├── JA3_RULES:       exact hash → OS identification (weight 0.8)
         └── VENDOR_RULES:    "Hikvision" → IoT camera (weight 0.85)
      3. Aggregate: device_type = highest sum of weights
                    os = highest sum of weights
                    confidence = min(sum/count, 1.0) × 100
      4. Generate CPE string (e.g. cpe:2.3:o:microsoft:windows_10:...)
  → writer.py — UPSERT inference_results + DELETE/INSERT evidence + UPDATE asset confidence
```

### Device Types phân loại

| Type | Mô tả | Ví dụ signals |
|---|---|---|
| **IoMT** | Thiết bị y tế kết nối | DICOM (port 104), HL7 (port 2575), GE/Philips/Siemens vendor, VxWorks/QNX OS |
| **IoT** | Thiết bị IoT | RTSP (port 554), MQTT (port 1883), camera Hikvision/Dahua/Axis |
| **Network** | Thiết bị mạng | SNMP (port 161), BGP (port 179), Cisco vendor/DHCP |
| **Workstation** | Máy trạm | RDP (port 3389), VNC (port 5900), Dell/HP/Lenovo vendor |
| **Server** | Máy chủ | VMware vendor OUI |
| **Scanner** | Công cụ quét | curl/python/Go-http/zgrab user-agent |
| **Unknown** | Chưa xác định | Không match rule nào, confidence = 5% |

### CLI Commands

```bash
# Ingest Zeek logs vào PostgreSQL
python -m passive_asset_intel ingest
python -m passive_asset_intel ingest --types dhcp conn --log-dir /path/to/logs
python -m passive_asset_intel ingest --file /path/to/conn.log --types conn

# Chạy inference phân loại thiết bị
python -m passive_asset_intel infer
python -m passive_asset_intel infer --dry-run    # In JSON, không ghi DB

# Ingest + inference liên tiếp
python -m passive_asset_intel run-all
```

---

## Frontend chi tiết

### Routes

| Route | Page | Dữ liệu |
|---|---|---|
| `/` | DashboardPage | `useStats()` — KPI cards, protocol pie chart, traffic area chart, top assets |
| `/assets` | AssetsPage | `useAssets()` — 4,640 assets, search/filter, protocols, confidence bar |
| `/assets/:id` | AssetDetailPage | `useAsset(id)` — IPs, fingerprints, behaviors, inference + evidence |
| `/network` | NetworkPage | `useConnections()` + `useBehaviors()` — connection flows, top ports chart |
| `/logs` | LogsPage | `useDns()` + `useTls()` + `useHttp()` — unified log view, type filter |
| `/alerts` | AlertsPage | Mock data — alert triage |
| `/vulnerabilities` | VulnerabilitiesPage | Mock data — CVE list |
| `/settings` | SettingsPage | Local state — user preferences |
| `/admin/*` | Admin pages | Mock/simulated data — system config, users, roles, rules, integrations |

### Data Flow

```
Page component
  → useApi.ts hook (TanStack Query, staleTime: 30s)
    → lib/api.ts — fetch('http://localhost:3001/api/...')
      → server/api.js — Express endpoint
        → PostgreSQL query
          → JSON response
            → React component renders
```

### Theme System

- Dark mode mặc định, toggle via sidebar
- Lưu trong `localStorage` key `hqg-theme`
- Recharts colors adapt via `useChartTheme()`

### Component Architecture

```
App.tsx
  └── QueryClientProvider (TanStack Query)
      └── ThemeProvider (Dark/Light)
          └── TooltipProvider (Radix)
              └── BrowserRouter
                  └── DashboardLayout
                      ├── AppSidebar (navigation)
                      └── <Outlet /> (page content)
```

---

## npm Scripts

| Script | Mô tả |
|---|---|
| `npm run dev` | **Chạy cả API + Frontend** song song (concurrently) |
| `npm run dev:ui` | Chỉ chạy Vite frontend |
| `npm run server` | Chỉ chạy Express API server |
| `npm run build` | Build production |
| `npm run lint` | ESLint check |
| `npm test` | Vitest unit tests |
| `npm run preview` | Preview production build |

---

## Thống kê source code

| Khu vực | LOC | Files |
|---|---|---|
| Frontend React (src/) | ~6,900 | 70+ |
| Express API (server/) | ~300 | 1 |
| Python Pipeline | ~2,700 | 22 |
| **Tổng** | **~10,000** | **~100** |

| Metric | Giá trị |
|---|---|
| Frontend pages | 15 |
| UI components (shadcn) | 52 |
| React hooks | 9 (API) + 3 (utility) |
| API endpoints | 9 |
| Database tables | 15 |
| Zeek parsers | 5 + base |
| Inference rules | 50+ |
| npm dependencies | 70 prod + 26 dev |
| Python dependencies | 3 |

---

## Ghi chú kỹ thuật quan trọng

1. **Zeek 8 dùng TSV, không phải JSON** — Parser đọc `#fields` header, xử lý `#unset_field` (`-`) và `#empty_field` (`(empty)`).

2. **Naive datetime** — PostgreSQL schema dùng `timestamp` (no timezone). Python dùng `datetime.utcfromtimestamp()`, không dùng timezone-aware datetime.

3. **MAC-first asset identification** — DHCP cung cấp MAC address. Khi không có MAC, dùng synthetic `ip:<addr>` làm `mac_address`.

4. **`statement_cache_size=0`** — asyncpg pool tắt prepared statement cache để tránh type conflict khi re-run.

5. **PostgreSQL `inet` type** — API dùng `host(ip_address)::text` để strip CIDR mask `/32`.

6. **Express 5** — Dùng Express 5.2.1 (major upgrade từ Express 4), chạy ESM (`"type": "module"` trong package.json).

7. **UPSERT pattern** — Tất cả write operations dùng `ON CONFLICT ... DO UPDATE` với unique constraints/indexes đã được gộp sẵn trong `schema.sql`.
