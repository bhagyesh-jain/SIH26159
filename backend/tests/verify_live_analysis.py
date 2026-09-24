"""
Verification Script for Phase 1 Live Forensic Capture Analysis
"""
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

import json
from scapy.all import wrpcap, Ether, IP, TCP, Raw
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models.database import init_db

def run_verification():
    print("=== SecureMailScope Phase 1 Live Verification ===")
    
    # Initialize DB tables
    init_db()

    # 1. Create a synthetic PCAP capture file
    temp_pcap = BASE_DIR / "storage" / "temp" / "verification_live_smtp.pcap"
    temp_pcap.parent.mkdir(parents=True, exist_ok=True)
    
    pkt1 = Ether() / IP(src="10.0.0.15", dst="10.0.0.100") / TCP(sport=49152, dport=25, flags="S")
    pkt2 = Ether() / IP(src="10.0.0.100", dst="10.0.0.15") / TCP(sport=25, dport=49152, flags="SA")
    pkt3 = Ether() / IP(src="10.0.0.15", dst="10.0.0.100") / TCP(sport=49152, dport=25, flags="A")
    pkt4 = Ether() / IP(src="10.0.0.100", dst="10.0.0.15") / TCP(sport=25, dport=49152, flags="PA") / Raw(load=b"220 postfix.local ESMTP\r\n")
    pkt5 = Ether() / IP(src="10.0.0.15", dst="10.0.0.100") / TCP(sport=49152, dport=25, flags="PA") / Raw(load=b"EHLO client.local\r\n")
    
    wrpcap(str(temp_pcap), [pkt1, pkt2, pkt3, pkt4, pkt5])
    print(f"1. Generated local synthetic PCAP at: {temp_pcap}")

    # 2. Use FastAPI TestClient context manager to trigger lifespan & test endpoints
    with TestClient(app) as client:
        # Health check
        health_resp = client.get("/api/v1/health")
        print(f"2. GET /api/v1/health -> {health_resp.status_code}: {health_resp.json()}")

        # Create investigation
        inv_resp = client.post("/api/v1/investigations", json={"title": "Verification Case SMTP-01"})
        inv = inv_resp.json()
        print(f"3. POST /api/v1/investigations -> ID: {inv['id']}, Title: '{inv['title']}'")

        # Upload capture
        with open(temp_pcap, "rb") as f:
            up_resp = client.post(
                f"/api/v1/investigations/{inv['id']}/captures",
                files={"file": ("verification_live_smtp.pcap", f, "application/octet-stream")}
            )
        cap = up_resp.json()
        print(f"4. POST /api/v1/investigations/{inv['id']}/captures -> Capture ID: {cap['id']}")
        print(f"   SHA-256 Hash: {cap['sha256']}")
        print(f"   Format: {cap['format']}")
        print(f"   TShark Version: {cap['tshark_version']}")

        # Check job status
        job_resp = client.get(f"/api/v1/jobs/{cap['job_id']}")
        print(f"5. GET /api/v1/jobs/{cap['job_id']} -> State: {job_resp.json()['state']}")

        # Query sessions
        sess_resp = client.get(f"/api/v1/investigations/{inv['id']}/sessions")
        sessions = sess_resp.json()
        print(f"6. GET /api/v1/investigations/{inv['id']}/sessions -> Extracted {len(sessions)} stream(s):")
        for s in sessions:
            print(f"   - Stream #{s['tcp_stream']}: {s['src']}:{s['src_port']} -> {s['dst']}:{s['dst_port']} | Protocol: {s['protocol']} | Events: {s['events_count']}")

        # Query session timeline detail
        if sessions:
            detail_resp = client.get(f"/api/v1/sessions/{sessions[0]['id']}")
            detail = detail_resp.json()
            print(f"7. GET /api/v1/sessions/{sessions[0]['id']} -> Packet timeline:")
            for evt in detail["events"]:
                obs = evt["observed_json"]
                print(f"   - Packet #{evt['packet_number']}: Protocol '{obs.get('protocol')}', Info: '{obs.get('info')}'")

    # Cleanup temp PCAP
    if temp_pcap.exists():
        temp_pcap.unlink()
    print("\n=== Phase 1 Verification Completed Successfully ===")

if __name__ == "__main__":
    run_verification()
