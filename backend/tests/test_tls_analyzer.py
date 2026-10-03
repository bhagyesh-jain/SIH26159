import pytest
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import UpgradeStatus
from backend.app.services.protocols.tls import (
    lookup_cipher_suite, normalize_tls_version, analyze_tls_stream
)

def create_mock_tls_packet(
    frame_num: int,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str = "TLSv1.3",
    tls_type: str = None,
    supported_ver: str = None,
    rec_ver: str = None,
    cipher: str = None,
    alert_lvl: str = None,
    alert_desc: str = None,
    info: str = ""
) -> NormalizedPacket:
    return NormalizedPacket(
        frame_number=frame_num,
        timestamp=1700000000.0 + frame_num,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=0,
        tcp_seq=100 * frame_num,
        tcp_ack=100 * frame_num,
        protocol_col=proto,
        info_col=info,
        tls_handshake_type=tls_type,
        tls_supported_version=supported_ver,
        tls_record_version=rec_ver,
        tls_ciphersuite=cipher,
        tls_alert_level=alert_lvl,
        tls_alert_desc=alert_desc
    )

def test_cipher_suite_lookup_pfs_vs_static_rsa():
    # 1. TLS 1.3 AES-256-GCM
    c13 = lookup_cipher_suite("0x1302")
    assert c13["name"] == "TLS_AES_256_GCM_SHA384"
    assert c13["pfs"] == "ENABLED"
    assert c13["mode"] == "AEAD"

    # 2. TLS 1.2 ECDHE with RSA Authentication (Forward Secrecy ENABLED)
    c_ecdhe = lookup_cipher_suite("0xc030")
    assert c_ecdhe["name"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert c_ecdhe["pfs"] == "ENABLED"
    assert c_ecdhe["kx"] == "ECDHE"

    # 3. TLS 1.2 Static RSA (NO Forward Secrecy)
    c_rsa = lookup_cipher_suite("0x002f")
    assert c_rsa["name"] == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert c_rsa["pfs"] == "NO_PFS_STATIC_RSA"
    assert c_rsa["kx"] == "STATIC_RSA"
    assert c_rsa["mode"] == "CBC"

def test_tls_version_disambiguation_rfc8446():
    # In TLS 1.3, record layer says 0x0303 (TLS 1.2) for middlebox compat,
    # but supported_versions extension specifies 0x0304 (TLS 1.3).
    assert normalize_tls_version("0x0304") == "TLSv1.3"
    assert normalize_tls_version("0x0303") == "TLSv1.2"

def test_analyze_tls_stream_tls13_negotiated():
    packets = [
        create_mock_tls_packet(1, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.2", tls_type="1", rec_ver="0x0301", info="Client Hello"),
        create_mock_tls_packet(2, "10.0.0.2", "10.0.0.1", 25, 50000, proto="TLSv1.3", tls_type="2", supported_ver="0x0304", rec_ver="0x0303", cipher="0x1302", info="Server Hello"),
        create_mock_tls_packet(3, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.3", rec_ver="0x0303", info="Application Data"),
        create_mock_tls_packet(4, "10.0.0.2", "10.0.0.1", 25, 50000, proto="TLSv1.3", rec_ver="0x0303", info="Application Data")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    result, events = analyze_tls_stream(stream, "SMTP", upgrade_accepted=True)

    assert result.handshake_status == "COMPLETED"
    assert result.upgrade_status == UpgradeStatus.NEGOTIATED
    assert result.tls_version_negotiated == "TLSv1.3"
    assert result.selected_cipher_hex == "0x1302"
    assert result.selected_cipher_name == "TLS_AES_256_GCM_SHA384"
    assert result.forward_secrecy == "ENABLED"
    assert "encrypted_cert_note" in result.details

def test_analyze_tls_stream_static_rsa_weak_cipher():
    packets = [
        create_mock_tls_packet(1, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.2", tls_type="1", rec_ver="0x0301", info="Client Hello"),
        create_mock_tls_packet(2, "10.0.0.2", "10.0.0.1", 25, 50000, proto="TLSv1.2", tls_type="2", rec_ver="0x0303", cipher="0x002f", info="Server Hello"),
        create_mock_tls_packet(3, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.2", rec_ver="0x0303", info="Application Data"),
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    result, events = analyze_tls_stream(stream, "SMTP", upgrade_accepted=True)

    assert result.handshake_status == "COMPLETED"
    assert result.upgrade_status == UpgradeStatus.NEGOTIATED
    assert result.tls_version_negotiated == "TLSv1.2"
    assert result.selected_cipher_hex == "0x002f"
    assert result.key_exchange == "STATIC_RSA"
    assert result.forward_secrecy == "NO_PFS_STATIC_RSA"
    assert result.security_rating == "WEAK_NO_PFS"

def test_analyze_tls_stream_fatal_alert():
    packets = [
        create_mock_tls_packet(1, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.2", tls_type="1", info="Client Hello"),
        create_mock_tls_packet(2, "10.0.0.2", "10.0.0.1", 25, 50000, proto="TLSv1.3", tls_type="2", supported_ver="0x0304", cipher="0x1302", info="Server Hello"),
        create_mock_tls_packet(3, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.3", alert_lvl="2", alert_desc="48", info="Alert (Level: Fatal, Description: Unknown CA)")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    result, events = analyze_tls_stream(stream, "SMTP", upgrade_accepted=True)

    assert result.handshake_status == "FAILED"
    assert result.upgrade_status == UpgradeStatus.FAILED
    assert result.tls_alert_level == "2"
    assert result.tls_alert_desc == "48"

def test_analyze_tls_stream_missing_server_hello():
    packets = [
        create_mock_tls_packet(1, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TLSv1.2", tls_type="1", info="Client Hello"),
        create_mock_tls_packet(2, "10.0.0.1", "10.0.0.2", 50000, 25, proto="TCP", info="[RST, ACK]")
    ]
    stream = NormalizedStream(tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP", packets=packets)

    result, events = analyze_tls_stream(stream, "SMTP", upgrade_accepted=True)

    assert result.handshake_status == "FAILED"
    assert result.upgrade_status == UpgradeStatus.FAILED
    assert result.tcp_reset is True
