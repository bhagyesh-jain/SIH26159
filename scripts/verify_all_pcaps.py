import json
import hashlib
import subprocess
from pathlib import Path

STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage" / "pcaps" / "synthetic"
MANIFEST_PATH = Path(__file__).resolve().parent.parent / "datasets" / "manifests" / "scenarios_manifest.json"
TSHARK_BIN = "C:\\Program Files\\Wireshark\\tshark.exe"

def verify_pcaps():
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)

    print("==========================================================================================")
    print("SCENARIO VERIFICATION REPORT")
    print("==========================================================================================")
    print(f"{'Scenario ID':<22} | {'Protocol':<8} | {'Packets':<7} | {'SHA-256 (First 12)':<16} | {'Status':<10}")
    print("------------------------------------------------------------------------------------------")

    for sc in manifest["scenarios"]:
        sc_id = sc["scenario_id"]
        pcap_file = STORAGE_DIR / sc["pcap_filename"]
        
        if not pcap_file.exists():
            print(f"{sc_id:<22} | {sc['protocol']:<8} | MISSING | N/A              | FAILED")
            continue

        h = hashlib.sha256(pcap_file.read_bytes()).hexdigest()
        
        # Run TShark to count packets and get detected protocol
        cmd = [TSHARK_BIN, "-r", str(pcap_file), "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Protocol"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        lines = [l for l in res.stdout.strip().split("\n") if l]
        pkt_count = len(lines)
        
        status = sc.get("verification_status", "UNKNOWN")
        print(f"{sc_id:<22} | {sc['protocol']:<8} | {pkt_count:<7} | {h[:12]:<16} | {status:<10}")

    print("==========================================================================================")

if __name__ == "__main__":
    verify_pcaps()
