#!/bin/sh
set -e

echo "[Dovecot] Waiting for SSL certificates in /certs..."
while [ ! -f /certs/server_valid.crt ]; do
  sleep 1
done

mkdir -p /var/mail/user /var/run/dovecot
chown -R 1000:1000 /var/mail

# Background watcher to reload Dovecot whenever certificates in /certs change
(
  LAST_MTIME=0
  while true; do
    if [ -f /certs/server_valid.crt ]; then
      CURRENT_MTIME=$(stat -c %Y /certs/server_valid.crt 2>/dev/null || echo 0)
      if [ "$LAST_MTIME" -ne 0 ] && [ "$CURRENT_MTIME" -ne "$LAST_MTIME" ]; then
        echo "[Dovecot Watcher] Certificates updated, reloading Dovecot..."
        dovecot reload || true
      fi
      LAST_MTIME=$CURRENT_MTIME
    fi
    sleep 1
  done
) &

exec dovecot -F
