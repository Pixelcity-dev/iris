#!/bin/sh
# Daily backup of the Iris dashboard scan store (metadata + reports).
# Installed on the VPS as /usr/local/bin/iris-backup.sh, cron:
#   30 3 * * * root /usr/local/bin/iris-backup.sh >> /var/log/iris-backup.log 2>&1
#
# Restore: docker compose stop dashboard, untar the archive over the
# volume _data dir (/var/lib/docker/volumes/iris-dashboard_iris_scans/_data),
# docker compose up -d.
set -eu
VOL=/var/lib/docker/volumes/iris-dashboard_iris_scans/_data
DEST=/var/backups/iris
KEEP=7
mkdir -p "$DEST"
stamp=$(date +%F-%H%M%S)
tmp="$DEST/.iris-$stamp.tgz.tmp"
tar czf "$tmp" -C "$VOL" .
mv "$tmp" "$DEST/iris-$stamp.tgz"
# rotate: keep newest KEEP archives
ls -1t "$DEST"/iris-*.tgz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r f; do
  rm -f "$f"
done
echo "iris-backup: $DEST/iris-$stamp.tgz ($(du -h "$DEST/iris-$stamp.tgz" | cut -f1))"
