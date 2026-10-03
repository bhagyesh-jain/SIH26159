import pytest
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import UpgradeStatus
from backend.app.services.protocols.imap import IMAPStateMachine
from backend.app.services.protocols.pop3 import POP3StateMachine

def create_mock_packet(frame_num: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, payload_str: str, proto: str = "TCP", tls_type: str = None) -> NormalizedPacket:
    payload_hex = payload_str.encode("latin1", errors="replace").hex() if payload_str else None
    return NormalizedPacket(
        frame_number=frame_num,
        timestamp=1700000000.0 + frame_num,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=0,
        tcp_seq=seq,
        tcp_ack=ack,
        protocol_col=proto,
        info_col="",
        tcp_payload_hex=payload_hex,
        plaintext_payload=payload_str,
        tls_handshake_type=tls_type
    )

# --- IMAP State Machine Tests ---

def test_imap_successful_starttls_upgrade():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 143, 50000, 1, 1, "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", proto="IMAP"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 143, 1, 60, "A01 CAPABILITY\r\n", proto="IMAP"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 143, 50000, 60, 16, "A01 OK Capabilities listed.\r\n", proto="IMAP"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 143, 16, 88, "A02 STARTTLS\r\n", proto="IMAP"),
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 143, 50000, 88, 30, "A02 OK Begin TLS negotiation now.\r\n", proto="IMAP"),
        create_mock_packet(6, "10.0.0.1", "10.0.0.2", 50000, 143, 30, 120, None, proto="TLSv1.3", tls_type="1"),
        create_mock_packet(7, "10.0.0.2", "10.0.0.1", 143, 50000, 120, 400, None, proto="TLSv1.3", tls_type="2"),
        create_mock_packet(8, "10.0.0.1", "10.0.0.2", 50000, 143, 400, 150, None, proto="TLSv1.3")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=143, protocol="IMAP", packets=packets)

    sm = IMAPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.NEGOTIATED
    types = [e.event_type for e in events]
    assert "CAPABILITY_ADVERTISED" in types
    assert "UPGRADE_REQUESTED" in types
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types

def test_imap_rejected_starttls_upgrade():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 143, 50000, 1, 1, "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", proto="IMAP"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 143, 1, 60, "A02 STARTTLS\r\n", proto="IMAP"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 143, 50000, 60, 16, "A02 NO TLS Unavailable\r\n", proto="IMAP")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=143, protocol="IMAP", packets=packets)

    sm = IMAPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.REJECTED
    types = [e.event_type for e in events]
    assert "UPGRADE_REJECTED" in types

def test_imap_starttls_offered_but_unused_and_password_redaction():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 143, 50000, 1, 1, "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", proto="IMAP"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 143, 1, 60, "A03 LOGIN secretuser SuperSecretPass123!\r\n", proto="IMAP")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=143, protocol="IMAP", packets=packets)

    sm = IMAPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.OFFERED_NOT_USED
    plaintext_event = [e for e in events if e.event_type == "PLAINTEXT_COMMAND_AFTER_OFFER"][0]
    
    # Assert password is NOT present in observed value
    assert "SuperSecretPass123!" not in plaintext_event.observed_value
    assert "[REDACTED]" in plaintext_event.observed_value

# --- POP3 State Machine Tests ---

def test_pop3_successful_stls_upgrade():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 110, 50000, 1, 1, "+OK Dovecot ready.\r\n", proto="POP3"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 110, 1, 22, "CAPA\r\n", proto="POP3"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 110, 50000, 22, 7, "+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n", proto="POP3"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 110, 7, 50, "STLS\r\n", proto="POP3"),
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 110, 50000, 50, 13, "+OK Begin TLS negotiation now.\r\n", proto="POP3"),
        create_mock_packet(6, "10.0.0.1", "10.0.0.2", 50000, 110, 13, 80, None, proto="TLSv1.3", tls_type="1"),
        create_mock_packet(7, "10.0.0.2", "10.0.0.1", 110, 50000, 80, 300, None, proto="TLSv1.3", tls_type="2"),
        create_mock_packet(8, "10.0.0.1", "10.0.0.2", 50000, 110, 300, 150, None, proto="TLSv1.3")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=110, protocol="POP3", packets=packets)

    sm = POP3StateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.NEGOTIATED
    types = [e.event_type for e in events]
    assert "CAPABILITY_ADVERTISED" in types
    assert "UPGRADE_REQUESTED" in types
    assert "UPGRADE_ACCEPTED" in types
    assert "TLS_NEGOTIATED" in types

def test_pop3_stls_offered_but_unused_and_password_redaction():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 110, 50000, 1, 1, "+OK Dovecot ready.\r\n", proto="POP3"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 110, 1, 22, "CAPA\r\n", proto="POP3"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 110, 50000, 22, 7, "+OK Capability list follows\r\nSTLS\r\n.\r\n", proto="POP3"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 110, 7, 50, "USER testuser\r\n", proto="POP3"),
        create_mock_packet(5, "10.0.0.1", "10.0.0.2", 50000, 110, 20, 50, "PASS TopSecretPass999\r\n", proto="POP3")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=110, protocol="POP3", packets=packets)

    sm = POP3StateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.OFFERED_NOT_USED
    plaintext_event = [e for e in events if e.event_type == "PLAINTEXT_COMMAND_AFTER_OFFER"][0]
    
    # Assert password is NOT present in observed value
    assert "TopSecretPass999" not in plaintext_event.observed_value
    assert "[REDACTED]" in sm._redact_pop3_line("PASS TopSecretPass999")

def test_imap_segmented_commands_and_retransmissions():
    # Segmented client command: "A01 " in frame 2, "STARTTLS\r\n" in frame 3
    # Retransmitted frame 3 as frame 4 with same sequence
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 143, 50000, 1, 1, "* OK [CAPABILITY IMAP4rev1 STARTTLS] Ready.\r\n", proto="IMAP"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 143, 1, 40, "A01 ", proto="IMAP"),
        create_mock_packet(3, "10.0.0.1", "10.0.0.2", 50000, 143, 5, 40, "STARTTLS\r\n", proto="IMAP"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 143, 5, 40, "STARTTLS\r\n", proto="IMAP"),  # Retransmission
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 143, 50000, 40, 15, "A01 OK Begin TLS negotiation.\r\n", proto="IMAP")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=143, protocol="IMAP", packets=packets)

    sm = IMAPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.ACCEPTED
    types = [e.event_type for e in events]
    assert "UPGRADE_REQUESTED" in types
    assert "UPGRADE_ACCEPTED" in types

def test_pop3_incomplete_capa_response_and_truncated_stream():
    # POP3 CAPA started but stream ends before termination '.'
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 110, 50000, 1, 1, "+OK Dovecot ready.\r\n", proto="POP3"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 110, 1, 7, "CAPA\r\n", proto="POP3"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 110, 50000, 7, 7, "+OK Capability list follows\r\nSTLS\r\n", proto="POP3") # Truncated, no ending '.'
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=110, protocol="POP3", packets=packets)

    sm = POP3StateMachine()
    events = sm.analyze_stream(stream)

    # Server greeting recorded, CAPA sent, but incomplete stream keeps status UNKNOWN
    assert sm.overall_status == UpgradeStatus.UNKNOWN
    types = [e.event_type for e in events]
    assert "SERVER_GREETING" in types
    assert "CLIENT_COMMAND" in types

def test_imap_malformed_payload_handling():
    # Stream containing garbage / binary payload lines
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 143, 50000, 1, 1, "\x00\x01\x02\xff\xfe\r\n", proto="IMAP"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 143, 1, 10, "INVALID_TAG_NO_SPACE\r\n", proto="IMAP")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=143, protocol="IMAP", packets=packets)

    sm = IMAPStateMachine()
    events = sm.analyze_stream(stream)

    # Does not crash, status remains UNKNOWN
    assert sm.overall_status == UpgradeStatus.UNKNOWN

