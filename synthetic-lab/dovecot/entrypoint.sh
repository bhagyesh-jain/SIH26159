#!/bin/sh
set -e

echo "[Dovecot] Waiting for SSL certificates in /certs..."
while [ ! -f /certs/server_valid.crt ]; do
  sleep 1
done

echo "[Dovecot] Certificates found. Starting Dovecot daemon..."
mkdir -p /var/mail/user /var/run/dovecot
chown -R 1000:1000 /var/mail

exec dovecot -F
