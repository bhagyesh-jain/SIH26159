#!/bin/sh
set -e

echo "[Postfix] Waiting for SSL certificates in /certs..."
while [ ! -f /certs/server_valid.crt ]; do
  sleep 1
done

echo "[Postfix] Certificates found. Starting Postfix daemon..."
postfix check
postfix start

echo "[Postfix] Tailing mail log..."
exec tail -f /var/log/postfix.log
