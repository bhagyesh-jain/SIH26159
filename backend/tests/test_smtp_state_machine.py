import pytest
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import UpgradeStatus, reassemble_stream_lines
from backend.app.services.protocols.smtp import SMTPStateMachine

def create_mock_packet(frame_num: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, payload_str: str, proto: str = "SMTP", tls_type: str = None) -> NormalizedPacket:
    payload_hex = payload_str.encode("ascii").hex() if payload_str else None
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

def test_smtp_plaintext_no_starttls_offered():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "220 server.mailnet ESMTP\r\n"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 23, "EHLO client.mailnet\r\n"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 25, 50000, 23, 22, "250-server.mailnet\r\n250 DSN\r\n"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 25, 22, 43, "MAIL FROM:<a@b.com>\r\n"),
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 25, 50000, 43, 42, "250 2.1.0 Ok\r\n")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    sm = SMTPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.NOT_OFFERED
    event_types = [e.event_type for e in events]
    assert "SERVER_GREETING" in event_types
    assert "CAPABILITY_ADVERTISED" in event_types

def test_smtp_successful_starttls_negotiation():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "220 server.mailnet ESMTP\r\n"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 23, "EHLO client.mailnet\r\n"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 25, 50000, 23, 22, "250-server.mailnet\r\n250-STARTTLS\r\n250 DSN\r\n"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 25, 22, 60, "STARTTLS\r\n"),
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 25, 50000, 60, 32, "220 2.0.0 Ready to start TLS\r\n"),
        create_mock_packet(6, "10.0.0.1", "10.0.0.2", 50000, 25, 32, 88, None, proto="TLSv1.3", tls_type="1"), # ClientHello
        create_mock_packet(7, "10.0.0.2", "10.0.0.1", 25, 50000, 88, 300, None, proto="TLSv1.3", tls_type="2"), # ServerHello
        create_mock_packet(8, "10.0.0.1", "10.0.0.2", 50000, 25, 300, 150, None, proto="TLSv1.3") # Post-ServerHello record exchange
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    sm = SMTPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.NEGOTIATED
    event_types = [e.event_type for e in events]
    assert "UPGRADE_ACCEPTED" in event_types
    assert "TLS_NEGOTIATED" in event_types

def test_smtp_starttls_offered_but_unused():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "220 server.mailnet ESMTP\r\n"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 23, "EHLO client.mailnet\r\n"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 25, 50000, 23, 22, "250-server.mailnet\r\n250-STARTTLS\r\n250 DSN\r\n"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 25, 22, 60, "MAIL FROM:<a@b.com>\r\n"),
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 25, 50000, 60, 42, "250 2.1.0 Ok\r\n")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    sm = SMTPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.OFFERED_NOT_USED
    event_types = [e.event_type for e in events]
    assert "PLAINTEXT_COMMAND_AFTER_OFFER" in event_types

def test_smtp_starttls_rejected_by_server():
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "220 server.mailnet ESMTP\r\n"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 23, "EHLO client.mailnet\r\n"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 25, 50000, 23, 22, "250-server.mailnet\r\n250-STARTTLS\r\n250 DSN\r\n"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 25, 22, 60, "STARTTLS\r\n"),
        create_mock_packet(5, "10.0.0.2", "10.0.0.1", 25, 50000, 60, 32, "554 5.7.0 TLS not available\r\n")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    sm = SMTPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.REJECTED
    event_types = [e.event_type for e in events]
    assert "UPGRADE_REJECTED" in event_types

def test_smtp_segmented_commands_and_retransmissions():
    # Segmented command: "START" in pkt 4, "TLS\r\n" in pkt 5
    # Retransmission: pkt 5 is retransmitted in pkt 6 with identical seq
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "220 server.mailnet ESMTP\r\n"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 23, "EHLO client.mailnet\r\n"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 25, 50000, 23, 22, "250-server.mailnet\r\n250-STARTTLS\r\n250 DSN\r\n"),
        create_mock_packet(4, "10.0.0.1", "10.0.0.2", 50000, 25, 22, 60, "START"),
        create_mock_packet(5, "10.0.0.1", "10.0.0.2", 50000, 25, 27, 60, "TLS\r\n"),
        create_mock_packet(6, "10.0.0.1", "10.0.0.2", 50000, 25, 27, 60, "TLS\r\n"), # Retransmission
        create_mock_packet(7, "10.0.0.2", "10.0.0.1", 25, 50000, 60, 32, "220 2.0.0 Ready\r\n")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    sm = SMTPStateMachine()
    events = sm.analyze_stream(stream)

    assert sm.overall_status == UpgradeStatus.ACCEPTED
    event_types = [e.event_type for e in events]
    assert "UPGRADE_REQUESTED" in event_types
    assert "UPGRADE_ACCEPTED" in event_types

def test_smtp_multiple_commands_in_single_segment():
    # Single segment contains EHLO and STARTTLS together
    packets = [
        create_mock_packet(1, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "220 server.mailnet ESMTP\r\n"),
        create_mock_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 23, "EHLO client.mailnet\r\nSTARTTLS\r\n"),
        create_mock_packet(3, "10.0.0.2", "10.0.0.1", 25, 50000, 23, 22, "250-server.mailnet\r\n250-STARTTLS\r\n250 DSN\r\n220 Ready\r\n")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    sm = SMTPStateMachine()
    events = sm.analyze_stream(stream)

    event_types = [e.event_type for e in events]
    assert "CLIENT_GREETING" in event_types
    assert "UPGRADE_REQUESTED" in event_types
