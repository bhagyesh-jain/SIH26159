import sys
import json
from pathlib import Path

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

def verify_stage_d():
    print("====================================================================================================")
    print("STAGE D — EVIDENCE-BASED TLS CRYPTOGRAPHIC ANALYSIS REPORT")
    print("====================================================================================================")

    for filename, proto_name, state_machine_cls in SCENARIOS:
        pcap_path = STORAGE_DIR / filename
        if not pcap_path.exists():
            print(f"[{filename}] MISSING FILE")
            continue

        raw_pkts = extract_packets_json(pcap_path)
        norm_pkts = [parse_raw_packet_to_normalized(p) for p in raw_pkts]

        streams_map = {}
        for p in norm_pkts:
            s_id = p.tcp_stream
            if s_id not in streams_map:
                streams_map[s_id] = NormalizedStream(
                    tcp_stream=s_id,
                    src_ip=p.src_ip,
                    dst_ip=p.dst_ip,
                    src_port=p.src_port,
                    dst_port=p.dst_port,
                    protocol=proto_name,
                    packets=[]
                )
            streams_map[s_id].packets.append(p)

        main_stream = max(streams_map.values(), key=lambda s: len(s.packets))
        sm = state_machine_cls()
        events = sm.analyze_stream(main_stream)

        print(f"\nScenario PCAP: {filename} ({proto_name})")
        print(f"  -> Overall Upgrade Status: {sm.overall_status.value}")
        print(f"  -> Security Events Detected ({len(events)}):")
        for evt in events:
            frames_str = ",".join(str(f) for f in evt.frame_numbers)
            details_summary = []
            if "tls_version" in evt.details:
                details_summary.append(f"Ver: {evt.details['tls_version']}")
            if "selected_cipher" in evt.details:
                details_summary.append(f"Cipher: {evt.details['selected_cipher']}")
            if "key_exchange" in evt.details:
                details_summary.append(f"KX: {evt.details['key_exchange']}")
            if "forward_secrecy" in evt.details:
                details_summary.append(f"PFS: {evt.details['forward_secrecy']}")
            if "security_rating" in evt.details:
                details_summary.append(f"Rating: {evt.details['security_rating']}")
            
            summary_str = " | ".join(details_summary) if details_summary else evt.observed_value[:40]
            print(f"      - [{evt.event_type:<28}] Frames: [{frames_str:<12}] | {summary_str}")

    print("\n====================================================================================================")

if __name__ == "__main__":
    verify_stage_d()
