import pytest
from pathlib import Path
from backend.app.services.tshark_adapter import extract_packets_json
from backend.app.schemas.normalized_packet import parse_raw_packet_to_normalized, NormalizedStream
from backend.app.services.protocols.base import UpgradeStatus
from backend.app.services.protocols.smtp import SMTPStateMachine

PCAPS_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "pcaps" / "synthetic"

def run_smtp_detection_on_pcap(filename: str):
    pcap_path = PCAPS_DIR / filename
    assert pcap_path.exists(), f"Synthetic PCAP file not found: {pcap_path}"

    raw_packets = extract_packets_json(pcap_path)
    norm_packets = [parse_raw_packet_to_normalized(p) for p in raw_packets]

    # Group by stream
    streams_map = {}
    for p in norm_packets:
        s_id = p.tcp_stream
        if s_id not in streams_map:
            streams_map[s_id] = NormalizedStream(
                tcp_stream=s_id,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol="SMTP",
                packets=[]
            )
        streams_map[s_id].packets.append(p)

    assert len(streams_map) > 0, f"No TCP streams found in {filename}"
    main_stream = max(streams_map.values(), key=lambda s: len(s.packets))

    sm = SMTPStateMachine()
    events = sm.analyze_stream(main_stream)
    return sm.overall_status, events


def test_scenario_scn_smtp_01():
    status, events = run_smtp_detection_on_pcap("SCN-SMTP-01.pcap")
    assert status == UpgradeStatus.NOT_OFFERED
    types = [e.event_type for e in events]
    assert "SERVER_GREETING" in types
    assert "CAPABILITY_ADVERTISED" in types

def test_scenario_scn_smtp_02():
    status, events = run_smtp_detection_on_pcap("SCN-SMTP-02.pcap")
    assert status == UpgradeStatus.NEGOTIATED
    types = [e.event_type for e in events]
    assert "UPGRADE_REQUESTED" in types
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types
    assert "TLS_CRYPTOGRAPHIC_ASSESSMENT" in types
    crypto_evt = [e for e in events if e.event_type == "TLS_CRYPTOGRAPHIC_ASSESSMENT"][0]
    assert crypto_evt.details["tls_version"] == "TLSv1.3"
    assert crypto_evt.details["forward_secrecy"] == "ENABLED"

def test_scenario_scn_smtp_03():
    status, events = run_smtp_detection_on_pcap("SCN-SMTP-03.pcap")
    assert status == UpgradeStatus.OFFERED_NOT_USED
    types = [e.event_type for e in events]
    assert "CAPABILITY_ADVERTISED" in types
    assert "PLAINTEXT_COMMAND_AFTER_OFFER" in types

def test_scenario_scn_tls12_baseline_01():
    status, events = run_smtp_detection_on_pcap("SCN-TLS12-BASELINE-01.pcap")
    assert status == UpgradeStatus.NEGOTIATED
    types = [e.event_type for e in events]
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types
    assert "TLS_CRYPTOGRAPHIC_ASSESSMENT" in types
    crypto_evt = [e for e in events if e.event_type == "TLS_CRYPTOGRAPHIC_ASSESSMENT"][0]
    assert crypto_evt.details["tls_version"] == "TLSv1.2"
    assert crypto_evt.details["key_exchange"] == "ECDHE"
    assert crypto_evt.details["forward_secrecy"] == "ENABLED"

def test_scenario_scn_tls_weak_01():
    status, events = run_smtp_detection_on_pcap("SCN-TLS-WEAK-01.pcap")
    assert status == UpgradeStatus.NEGOTIATED
    types = [e.event_type for e in events]
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types
    assert "TLS_CRYPTOGRAPHIC_ASSESSMENT" in types
    crypto_evt = [e for e in events if e.event_type == "TLS_CRYPTOGRAPHIC_ASSESSMENT"][0]
    assert crypto_evt.details["tls_version"] == "TLSv1.2"
    assert crypto_evt.details["key_exchange"] == "STATIC_RSA"
    assert crypto_evt.details["forward_secrecy"] == "NO_PFS_STATIC_RSA"
    assert crypto_evt.details["security_rating"] == "WEAK_NO_PFS"


def test_scenario_scn_tls_self_signed_01():
    status, events = run_smtp_detection_on_pcap("SCN-TLS-SELF-SIGNED-01.pcap")
    assert status == UpgradeStatus.FAILED
    types = [e.event_type for e in events]
    assert "UPGRADE_ACCEPTED" in types
    assert "HANDSHAKE_FAILED" in types

def test_scenario_scn_tls_expired_01():
    status, events = run_smtp_detection_on_pcap("SCN-TLS-EXPIRED-01.pcap")
    assert status == UpgradeStatus.FAILED
    types = [e.event_type for e in events]
    assert "UPGRADE_ACCEPTED" in types
    assert "HANDSHAKE_FAILED" in types

def test_scenario_scn_tls_interrupted_01():
    status, events = run_smtp_detection_on_pcap("SCN-TLS-INTERRUPTED-01.pcap")
    assert status == UpgradeStatus.FAILED
    types = [e.event_type for e in events]
    assert "UPGRADE_ACCEPTED" in types
    assert "HANDSHAKE_FAILED" in types


from backend.app.services.protocols.imap import IMAPStateMachine
from backend.app.services.protocols.pop3 import POP3StateMachine

def run_imap_detection_on_pcap(filename: str):
    pcap_path = PCAPS_DIR / filename
    assert pcap_path.exists(), f"Synthetic PCAP file not found: {pcap_path}"

    raw_packets = extract_packets_json(pcap_path)
    norm_packets = [parse_raw_packet_to_normalized(p) for p in raw_packets]

    streams_map = {}
    for p in norm_packets:
        s_id = p.tcp_stream
        if s_id not in streams_map:
            streams_map[s_id] = NormalizedStream(
                tcp_stream=s_id,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol="IMAP",
                packets=[]
            )
        streams_map[s_id].packets.append(p)

    assert len(streams_map) > 0, f"No TCP streams found in {filename}"
    main_stream = max(streams_map.values(), key=lambda s: len(s.packets))

    sm = IMAPStateMachine()
    events = sm.analyze_stream(main_stream)
    return sm.overall_status, events

def run_pop3_detection_on_pcap(filename: str):
    pcap_path = PCAPS_DIR / filename
    assert pcap_path.exists(), f"Synthetic PCAP file not found: {pcap_path}"

    raw_packets = extract_packets_json(pcap_path)
    norm_packets = [parse_raw_packet_to_normalized(p) for p in raw_packets]

    streams_map = {}
    for p in norm_packets:
        s_id = p.tcp_stream
        if s_id not in streams_map:
            streams_map[s_id] = NormalizedStream(
                tcp_stream=s_id,
                src_ip=p.src_ip,
                dst_ip=p.dst_ip,
                src_port=p.src_port,
                dst_port=p.dst_port,
                protocol="POP3",
                packets=[]
            )
        streams_map[s_id].packets.append(p)

    assert len(streams_map) > 0, f"No TCP streams found in {filename}"
    main_stream = max(streams_map.values(), key=lambda s: len(s.packets))

    sm = POP3StateMachine()
    events = sm.analyze_stream(main_stream)
    return sm.overall_status, events


def test_scenario_scn_imap_01():
    status, events = run_imap_detection_on_pcap("SCN-IMAP-01.pcap")
    types = [e.event_type for e in events]
    assert "CAPABILITY_ADVERTISED" in types
    assert "UPGRADE_REQUESTED" in types
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types
    assert "HANDSHAKE_FAILED" not in types
    assert status == UpgradeStatus.NEGOTIATED

def test_scenario_scn_pop3_01():
    status, events = run_pop3_detection_on_pcap("SCN-POP3-01.pcap")
    types = [e.event_type for e in events]
    assert "SERVER_GREETING" in types
    assert "CAPABILITY_ADVERTISED" in types
    assert "UPGRADE_REQUESTED" in types
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types
    assert "HANDSHAKE_FAILED" not in types
    assert status == UpgradeStatus.NEGOTIATED

def test_successful_upgrade_scenarios_contain_no_fatal_tls_alerts():
    """Regression test: Ensures successful upgrade PCAPs contain no fatal TLS alerts."""
    for pcap_filename in ["SCN-SMTP-02.pcap", "SCN-IMAP-01.pcap", "SCN-POP3-01.pcap"]:
        pcap_path = PCAPS_DIR / pcap_filename
        assert pcap_path.exists()
        raw_packets = extract_packets_json(pcap_path)
        norm_packets = [parse_raw_packet_to_normalized(p) for p in raw_packets]

        fatal_alerts = [
            p for p in norm_packets
            if str(p.tls_alert_level) == "2" or "Fatal" in (p.info_col or "")
        ]
        assert len(fatal_alerts) == 0, f"Successful scenario {pcap_filename} contained fatal TLS alerts on frames: {[p.frame_number for p in fatal_alerts]}"


