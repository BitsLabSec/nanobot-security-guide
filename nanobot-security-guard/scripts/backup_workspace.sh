#!/usr/bin/env bash

# nanobot-security-guard: Disaster Recovery & Backup Script
# Automatically creates an archive of the active workspace and rotates old backups.

set -e

WORKSPACE_DIR="${HOME}/.nanobot/workspace"
BACKUP_DIR="${HOME}/.nanobot/backups"
RETENTION_DAYS=7

if [ ! -d "$WORKSPACE_DIR" ]; then
    echo "[!] Workspace directory not found at $WORKSPACE_DIR. Skipping backup."
    exit 0
fi

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/workspace_backup_${TIMESTAMP}.tar.gz"

echo "[*] Initiating Nanobot Disaster Recovery Backup..."
echo "[*] Compressing $WORKSPACE_DIR -> $BACKUP_FILE"

# Create the tar archive, excluding any temporary hidden folders if needed (like macOS .DS_Store)
tar -czf "$BACKUP_FILE" -C "${HOME}/.nanobot" "workspace" --exclude=".DS_Store" > /dev/null 2>&1

if [ -f "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -sh "$BACKUP_FILE" | awk '{print $1}')
    echo "[✓] Backup successful. Archive size: $BACKUP_SIZE"
else
    echo "[X] Backup failed. Archive was not created."
    exit 1
fi

# Rotate old backups
echo "[*] Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "workspace_backup_*.tar.gz" -type f -mtime +${RETENTION_DAYS} -exec rm -f {} \;
echo "[✓] Cleanup complete."
