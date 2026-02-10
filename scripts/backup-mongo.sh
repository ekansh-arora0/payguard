#!/usr/bin/env bash
# MongoDB backup script — run via cron or manually.
# Usage: ./scripts/backup-mongo.sh
#
# Cron example (daily at 2 AM):
#   0 2 * * * /path/to/payguard/scripts/backup-mongo.sh >> /var/log/payguard-backup.log 2>&1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_DIR/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="payguard_mongo_${TIMESTAMP}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-7}"

# Load env vars if .env exists
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

MONGO_HOST="${MONGO_HOST:-localhost}"
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_USER="${MONGO_ROOT_USER:-payguard_admin}"
MONGO_PASS="${MONGO_ROOT_PASSWORD:?MONGO_ROOT_PASSWORD not set}"
DB_NAME="${DB_NAME:-payguard}"

mkdir -p "$BACKUP_DIR"

echo "[$(date -Iseconds)] Starting backup: $BACKUP_NAME"

# If running inside docker network, use docker exec; otherwise use local mongodump
if command -v mongodump &>/dev/null; then
    mongodump \
        --host="$MONGO_HOST" \
        --port="$MONGO_PORT" \
        --username="$MONGO_USER" \
        --password="$MONGO_PASS" \
        --authenticationDatabase=admin \
        --db="$DB_NAME" \
        --out="$BACKUP_DIR/$BACKUP_NAME" \
        --gzip
elif docker compose version &>/dev/null; then
    echo "mongodump not found locally, using docker exec..."
    CONTAINER=$(docker compose -f "$PROJECT_DIR/docker-compose.prod.yml" ps -q mongodb 2>/dev/null || \
                docker compose -f "$PROJECT_DIR/docker-compose.yml" ps -q mongodb 2>/dev/null)
    if [ -z "$CONTAINER" ]; then
        echo "ERROR: MongoDB container not running"
        exit 1
    fi
    docker exec "$CONTAINER" mongodump \
        --username="$MONGO_USER" \
        --password="$MONGO_PASS" \
        --authenticationDatabase=admin \
        --db="$DB_NAME" \
        --archive --gzip > "$BACKUP_DIR/${BACKUP_NAME}.archive.gz"
else
    echo "ERROR: Neither mongodump nor docker compose found"
    exit 1
fi

# Prune old backups
echo "Pruning backups older than $KEEP_DAYS days..."
find "$BACKUP_DIR" -name "payguard_mongo_*" -mtime +"$KEEP_DAYS" -exec rm -rf {} + 2>/dev/null || true

BACKUP_SIZE=$(du -sh "$BACKUP_DIR/$BACKUP_NAME"* 2>/dev/null | cut -f1)
echo "[$(date -Iseconds)] Backup complete: $BACKUP_NAME ($BACKUP_SIZE)"
