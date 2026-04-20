#!/usr/bin/env bash
# ==============================================================================
# Hospital Shield — one-shot deployment script.
#
# Chay 1 lenh la cai + tao admin (prompt interactive) + seed mock data + start.
#
#   ./setup.sh                 — full install + seed mock data + start
#   ./setup.sh --no-seed       — install without mock data
#   ./setup.sh --reset         — wipe database, rebuild, reseed
#   ./setup.sh --domain <fqdn> — set API_CORS_ORIGINS to include that domain
#   ./setup.sh --assets <N>    — seed N mock assets (default 60)
#
# Se hoi username/password admin ngay khi chay (khong bat buoc do dai).
# Safe to re-run: each step is idempotent.
# ==============================================================================

set -Eeuo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
    C_RESET=$'\033[0m'
else
    C_BOLD=; C_DIM=; C_GREEN=; C_YELLOW=; C_RED=; C_CYAN=; C_RESET=
fi
log()  { printf '%s==>%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%s ✓%s  %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s ⚠%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s ✗%s  %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ── Args ────────────────────────────────────────────────────────────────────
DO_SEED=1
DO_RESET=0
DOMAIN=""
ADMIN_USER=""
ADMIN_PASSWORD=""
TARGET_ASSETS="${TARGET_ASSETS:-60}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-seed)        DO_SEED=0 ;;
        --reset)          DO_RESET=1 ;;
        --domain)         shift; DOMAIN="${1:-}" ;;
        --assets)         shift; TARGET_ASSETS="${1:-60}" ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
    shift
done

# ── Prompt for admin credentials up front ──────────────────────────────────
echo
echo "${C_BOLD}Tao tai khoan admin cho Hospital Shield${C_RESET}"
while [[ -z "$ADMIN_USER" ]]; do
    read -r -p "  Username: " ADMIN_USER
done
while [[ -z "$ADMIN_PASSWORD" ]]; do
    read -r -s -p "  Password: " ADMIN_PASSWORD
    echo
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        warn "Password khong duoc de trong — nhap lai"
    fi
done
echo

# ── Pre-flight ──────────────────────────────────────────────────────────────
cd "$(dirname "$0")"
[[ -f docker-compose.yml ]] || die "docker-compose.yml not found — run setup.sh from the repo root."

if [[ $EUID -ne 0 ]] && ! groups | grep -qw docker; then
    warn "You are not root and not in the 'docker' group — Docker commands may require sudo."
fi

# ── 1. Install Docker if missing ────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    log "Docker not found — installing via get.docker.com"
    curl -fsSL https://get.docker.com | sh
    ok "Docker installed"
else
    ok "Docker already installed: $(docker --version)"
fi

# Pick the compose command (plugin v2 preferred)
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    log "Installing docker compose plugin"
    apt-get update -y && apt-get install -y docker-compose-plugin || die "Could not install docker compose plugin"
    COMPOSE="docker compose"
fi
ok "Using compose command: $COMPOSE"

# ── 2. Create .env if missing ───────────────────────────────────────────────
if [[ ! -f .env ]]; then
    log "Creating .env from .env.example"
    cp .env.example .env

    DB_PASS="$(openssl rand -hex 16)"
    JWT_SECRET="$(openssl rand -hex 32)"

    # Detect the public IP for CORS (best-effort — fallback to *)
    PUBLIC_IP="$(curl -fsSL --max-time 3 https://api.ipify.org || true)"
    CORS_ORIGINS="http://localhost,http://localhost:8080"
    if [[ -n "$PUBLIC_IP" ]]; then
        CORS_ORIGINS="$CORS_ORIGINS,http://$PUBLIC_IP"
    fi
    if [[ -n "$DOMAIN" ]]; then
        CORS_ORIGINS="$CORS_ORIGINS,http://$DOMAIN,https://$DOMAIN"
    fi

    # Figure out a reasonable LOCAL_SUBNETS guess — prefer the host's primary /24
    HOST_SUBNET=""
    if command -v ip >/dev/null 2>&1; then
        HOST_SUBNET="$(ip -o -4 route show to default | awk '{print $5}' | head -n1 \
                        | xargs -I{} ip -o -4 addr show dev {} 2>/dev/null | awk '{print $4}' | head -n1 \
                        | awk -F/ '{split($1,a,"."); print a[1]"."a[2]"."a[3]".0/24"}' )"
    fi
    LOCAL_SUBNETS="${HOST_SUBNET:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

    # Rewrite placeholders in .env (GNU sed)
    sed -i \
        -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PASS|" \
        -e "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=$JWT_SECRET|" \
        -e "s|^API_CORS_ORIGINS=.*|API_CORS_ORIGINS=$CORS_ORIGINS|" \
        -e "s|^LOCAL_SUBNETS=.*|LOCAL_SUBNETS=$LOCAL_SUBNETS|" \
        .env

    # For mock deploys without a real Zeek sensor, point the mount at a local empty folder
    if ! grep -q '^ZEEK_HOST_LOG_DIR=' .env; then
        echo "ZEEK_HOST_LOG_DIR=./zeek-logs" >> .env
    else
        sed -i "s|^ZEEK_HOST_LOG_DIR=.*|ZEEK_HOST_LOG_DIR=./zeek-logs|" .env
    fi
    mkdir -p ./zeek-logs

    ok "Generated .env (DB password + JWT secret + CORS + LOCAL_SUBNETS=$LOCAL_SUBNETS)"
else
    ok ".env already exists — leaving it alone"
    mkdir -p ./zeek-logs
fi

# Make sure the mock-log folder exists regardless
mkdir -p ./zeek-logs

# ── 3. Reset (optional) ─────────────────────────────────────────────────────
if [[ "$DO_RESET" -eq 1 ]]; then
    log "Resetting — bringing stack down + removing postgres volume"
    $COMPOSE down -v || true
fi

# ── 3b. Cleanup stale Docker state ──────────────────────────────────────────
# Cleans up leftovers from previous runs that can cause weird build/pull
# failures (dangling images, broken builder cache, IPv6-only DNS, stopped
# containers from a prior setup attempt).
log "Cleaning up stale Docker state"

# Stop + remove any old containers/networks from this project
$COMPOSE down --remove-orphans 2>/dev/null || true

# Remove any dangling containers with our project name still lingering
for cname in $(docker ps -aq --filter "name=hospital-shield-dash" 2>/dev/null); do
    docker rm -f "$cname" >/dev/null 2>&1 || true
done

# Prune dangling images + build cache (safe — keeps images still in use)
docker image prune -f >/dev/null 2>&1 || true
docker builder prune -f >/dev/null 2>&1 || true

# Force IPv4 for Docker daemon — many VPS providers (including this one)
# advertise AAAA records but have no IPv6 route, so pulls from Docker Hub
# fail with "network is unreachable". Setting ipv6:false + explicit IPv4
# DNS fixes it permanently.
if [[ ! -f /etc/docker/daemon.json ]] || ! grep -q '"ipv6"' /etc/docker/daemon.json 2>/dev/null; then
    log "Configuring Docker daemon for IPv4-only pulls"
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<'EOF'
{
  "dns": ["8.8.8.8", "1.1.1.1"],
  "ipv6": false
}
EOF
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart docker || true
        # Give the daemon a moment to come back up
        for _ in 1 2 3 4 5; do
            docker info >/dev/null 2>&1 && break
            sleep 1
        done
    fi
    ok "Docker daemon restarted with IPv4-only config"
fi

# Pre-pull base images so build doesn't die mid-way on flaky networks
log "Pre-pulling base images (skip if already cached)"
for img in nginx:1.27-alpine node:20-alpine python:3.12-slim postgres:16-alpine redis:7-alpine; do
    if ! docker image inspect "$img" >/dev/null 2>&1; then
        docker pull "$img" || warn "Could not pre-pull $img — build step will retry"
    fi
done
ok "Docker state cleaned"

# ── 4. Build + start ────────────────────────────────────────────────────────
log "Building images (first run can take 3–5 minutes)"
$COMPOSE build

log "Starting stack"
$COMPOSE up -d

# ── 5. Wait for the API to come up ──────────────────────────────────────────
log "Waiting for the API to become healthy..."
API_URL="http://localhost:3001/health"
deadline=$(( $(date +%s) + 120 ))
until curl -fsS "$API_URL" >/dev/null 2>&1; do
    if [[ $(date +%s) -gt $deadline ]]; then
        warn "API did not become healthy in 120s. Showing last logs:"
        $COMPOSE logs --tail=80 app || true
        die "Giving up."
    fi
    sleep 2
done
ok "API is up: $API_URL"

# ── 6. Create admin account ─────────────────────────────────────────────────
log "Creating admin account '$ADMIN_USER'"
$COMPOSE exec -T app python -m passive_asset_intel.scripts.create_admin \
    --username "$ADMIN_USER" \
    --password "$ADMIN_PASSWORD" \
    --role admin
ok "Admin account ready"

# ── 7. Seed mock data ───────────────────────────────────────────────────────
if [[ "$DO_SEED" -eq 1 ]]; then
    log "Seeding mock hospital-network data ($TARGET_ASSETS assets)"
    $COMPOSE exec -T app python -m passive_asset_intel.scripts.seed_mock_data \
        --assets "$TARGET_ASSETS"
    ok "Mock data seeded"
else
    warn "Skipping mock-data seed (--no-seed)"
fi

# ── 8. Summary ──────────────────────────────────────────────────────────────
PUBLIC_IP="$(curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null || true)"
echo
echo "${C_BOLD}======================================================================${C_RESET}"
echo "${C_BOLD}  Hospital Shield is ready.${C_RESET}"
echo "${C_BOLD}======================================================================${C_RESET}"
echo
echo "  Web UI:"
echo "    • http://localhost/                  (on this host)"
[[ -n "$PUBLIC_IP" ]] && echo "    • http://$PUBLIC_IP/                 (public)"
[[ -n "$DOMAIN" ]]    && echo "    • http://$DOMAIN/                    (domain)"
echo
echo "  Admin credentials:"
echo "    • username: ${C_BOLD}$ADMIN_USER${C_RESET}"
echo "    • password: ${C_BOLD}(cai ban vua nhap)${C_RESET}"
echo
echo "  Useful commands:"
echo "    $COMPOSE logs -f app        # tail API logs"
echo "    $COMPOSE ps                 # container status"
echo "    $COMPOSE down               # stop everything"
echo "    ./setup.sh --reset          # wipe + reinstall"
echo
echo "${C_DIM}Secrets live in .env — keep that file out of version control.${C_RESET}"
