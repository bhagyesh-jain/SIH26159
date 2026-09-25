#!/bin/sh
set -e

echo "[Generator Entrypoint] Step 1: Generating SSL Certificates..."
python /app/generate_certs.py

echo "[Generator Entrypoint] Step 2: Executing Traffic Scenarios..."
python /app/generate_scenarios.py

echo "[Generator Entrypoint] Done!"
