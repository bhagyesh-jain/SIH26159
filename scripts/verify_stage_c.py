import sys
import json
from pathlib import Path

# Add workspace root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.services.tshark_adapter import extract_packets_json
from backend.app.schemas.normalized_packet import parse_raw_packet_to_normalized, NormalizedStream
from backend.app.services.protocols.smtp import SMTPStateMachine
from backend.app.services.protocols.imap import IMAPStateMachine
from backend.app.services.protocols.pop3 import POP3StateMachine

STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage" / "pcaps" / "synthetic"

SCENARIOS = [
    ("SCN-SMTP-01.pcap", "SMTP", SMTPStateMachine),
    ("SCN-SMTP-02.pcap", "SMTP", SMTPStateMachine),
    ("SCN-SMTP-03.pcap", "SMTP", SMTPStateMachine),
    ("SCN-TLS12-BASELINE-01.pcap", "SMTP", SMTPStateMachine),
    ("SCN-TLS-WEAK-01.pcap", "SMTP", SMTPStateMachine),
    ("SCN-TLS-SELF-SIGNED-01.pcap", "SMTP", SMTPStateMachine),
    ("SCN-TLS-EXPIRED-01.pcap", "SMTP", SMTPStateMachine),
    ("SCN-TLS-INTERRUPTED-01.pcap", "SMTP", SMTPStateMachine),
    ("SCN-IMAP-01.pcap", "IMAP", IMAPStateMachine),
    ("SCN-POP3-01.pcap", "POP3", POP3StateMachine)
]

def verify_stage_c():
    print("====================================================================================================")
    print("STAGE C — PASSIVE SMTP / IMAP / POP3 STARTTLS STATE MACHINE DETECTION REPORT")
    print("====================================================================================================")

    for filename, proto_name, state_machine_cls in SCENARIOS:
        pcap_path = STORAGE_DIR / filename
        if not pcap_path.exists():
            print(f"[{filename}] MISSING FILE")
            continue

        raw_pkts = extract_packets_json(pcap_path)
        norm_pkts = [parse_raw_packet_to_normalized(p) for p in raw_pkts]

        stream = NormalizedStream(
            tcp_stream=0,
            src_ip=norm_pkts[0].src_ip if norm_pkts else "",
            dst_ip=norm_pkts[0].dst_ip if norm_pkts else "",
            src_port=norm_pkts[0].src_port if norm_pkts else 0,
            dst_port=norm_pkts[0].dst_port if norm_pkts else 0,
            protocol=proto_name,
            packets=norm_pkts
        )

        sm = state_machine_cls()
        events = sm.analyze_stream(stream)

        print(f"\nScenario PCAP: {filename} ({proto_name})")
        print(f"  -> Final Upgrade Status: {sm.overall_status.value}")
        print(f"  -> Detected Events ({len(events)}):")
        for evt in events:
            frames_str = ",".join(str(f) for f in evt.frame_numbers)
            print(f"      - Type: {evt.event_type:<28} | Value: {evt.observed_value[:35]:<35} | Frames: [{frames_str}]")

    print("\n====================================================================================================")

if __name__ == "__main__":
    verify_stage_c()
