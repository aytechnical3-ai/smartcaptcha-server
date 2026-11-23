#!/usr/bin/env bash
# ============================================================================
# SmartCaptcha — 1-Click Hetzner Ubuntu VPS Setup Script
# Run inside your Hetzner server (or paste into Hetzner Cloud-Init box):
#   1. Upload scale-server.ts, hetzner_full_schema.sql, docker-compose.scale.yml
#      to /opt/smartcaptcha
#   2. Run: bash hetzner-install.sh
# ============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

echo ">>> [1/5] Installing Docker, Firewall & Swap Tuning..."
apt-get update -y
apt-get install -y curl openssl ufw
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi

TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "${TOTAL_RAM_MB:-2048}" -lt 4096 ] && [ ! -f /swapfile ]; then
  echo ">>> Adding 2GB swap safety file for ${TOTAL_RAM_MB}MB RAM server..."
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

if [ "${TOTAL_RAM_MB:-2048}" -lt 1500 ]; then
  PG_SB="256MB"; PG_EC="768MB"; PG_WM="4MB"; RD_MM="256mb"
elif [ "${TOTAL_RAM_MB:-2048}" -lt 3500 ]; then
  PG_SB="512MB"; PG_EC="1536MB"; PG_WM="4MB"; RD_MM="384mb"
else
  PG_SB="1GB"; PG_EC="2560MB"; PG_WM="8MB"; RD_MM="512mb"
fi

ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable || true

echo ">>> [2/5] Generating secure .env credentials (RAM=${TOTAL_RAM_MB}MB, PG=${PG_SB})..."
if [ ! -f "$APP_DIR/.env" ]; then
  PG_PASS="$(openssl rand -hex 20)"
  JWT_SEC="$(openssl rand -hex 32)"
  CAP_SEC="$(openssl rand -hex 32)"
  ADM_PASS="$(openssl rand -base64 14 | tr -dc 'A-Za-z0-9' | head -c 14)"

  cat > "$APP_DIR/.env" <<EOF
POSTGRES_PASSWORD=$PG_PASS
JWT_SECRET=$JWT_SEC
CAPTCHA_HMAC_SECRET=$CAP_SEC
ADMIN_EMAILS=ak84839100@gmail.com
ADMIN_EMAIL=ak84839100@gmail.com
ADMIN_PASSWORD=$ADM_PASS
TURNSTILE_SECRET_KEY=
PG_SHARED_BUFFERS=$PG_SB
PG_EFFECTIVE_CACHE=$PG_EC
PG_WORK_MEM=$PG_WM
REDIS_MAXMEMORY=$RD_MM
EOF
  echo ">>> Admin Login Created: ak84839100@gmail.com | Password: $ADM_PASS"
fi

echo ">>> [3/4] Checking required files..."
for f in docker-compose.scale.yml hetzner_full_schema.sql scale-server.ts; do
  if [ ! -f "$APP_DIR/$f" ]; then
    echo "ERROR: Missing $APP_DIR/$f — upload this file from the SmartCaptcha downloads zip first."
    exit 1
  fi
done

echo ">>> [4/5] Starting PostgreSQL + PgBouncer + Redis + Bun API..."
docker compose -f docker-compose.scale.yml up -d
sleep 5

echo ">>> [5/5] Enabling daily automatic PostgreSQL backups (7-day retention)..."
mkdir -p "$APP_DIR/backups"
cat > "$APP_DIR/backup-db.sh" <<BKEOF
#!/usr/bin/env bash
cd "$APP_DIR"
docker compose -f docker-compose.scale.yml exec -T db pg_dump -U postgres smartcaptcha | gzip > "$APP_DIR/backups/db-\$(date +%F).sql.gz"
find "$APP_DIR/backups" -name "db-*.sql.gz" -mtime +7 -delete
BKEOF
chmod +x "$APP_DIR/backup-db.sh"
(crontab -l 2>/dev/null | grep -v "backup-db.sh"; echo "30 21 * * * $APP_DIR/backup-db.sh >/dev/null 2>&1") | crontab - || true

IP_ADDR=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
echo "=================================================================="
echo "SmartCaptcha Production Server (PostgreSQL + Redis) is LIVE!"
echo "Health check: http://$IP_ADDR/health"
echo "Daily DB Backups: $APP_DIR/backups/"
echo "Set Cloudflare DNS A record (api.yourdomain.com -> $IP_ADDR, Proxied)"
echo "Then put https://api.yourdomain.com in index.html & admin.html!"
echo "=================================================================="
