import json
import uuid
import datetime
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.services.tshark_adapter import extract_packets_json
from backend.app.schemas.normalized_packet import parse_raw_packet_to_normalized, NormalizedPacket
from backend.app.models.database import Base, Investigation, Capture, Session as DbSessionModel, SecurityEvent, ensure_schema_migrated

PCAP_PATH = Path(__file__).resolve().parent.parent.parent / "storage" / "pcaps" / "synthetic" / "SCN-SMTP-02.pcap"

def test_tshark_extraction_supported_fields():
    """Verify TShark extraction returns both Phase 1 fields and extended Stage A TLS/TCP fields."""
    assert PCAP_PATH.exists(), f"Sample PCAP not found at {PCAP_PATH}"
    packets = extract_packets_json(PCAP_PATH)
    assert len(packets) > 0

    first_pkt = packets[0]
    layers = first_pkt.get("_source", {}).get("layers", {})

    # Check Phase 1 backward-compatible fields
    assert "frame.number" in layers
    assert "ip.src" in layers
    assert "tcp.stream" in layers

    # Check Stage A extended fields presence
    assert "tcp.seq" in layers
    assert "tcp.ack" in layers

def test_normalized_packet_parser():
    """Verify parsing raw TShark packet dictionary into NormalizedPacket schema."""
    raw_packet = {
        "_source": {
            "layers": {
                "frame.number": ["10"],
                "frame.time_epoch": ["1700000000.123456"],
                "ip.src": ["192.168.1.10"],
                "ip.dst": ["192.168.1.20"],
                "tcp.srcport": ["12345"],
                "tcp.dstport": ["25"],
                "tcp.stream": ["2"],
                "tcp.seq": ["100"],
                "tcp.ack": ["200"],
                "_ws.col.Protocol": ["SMTP"],
                "_ws.col.Info": ["S: 220 2.0.0 Ready"],
                "tcp.payload": ["32323020322e302e302052656164790d0a"], # 220 2.0.0 Ready\r\n
                "tls.record.version": ["0x0303"],
                "tls.handshake.type": ["1"],
                "tls.handshake.extensions.supported_version": ["0x0304"]
            }
        }
    }

    norm = parse_raw_packet_to_normalized(raw_packet)

    assert isinstance(norm, NormalizedPacket)
    assert norm.frame_number == 10
    assert norm.timestamp == 1700000000.123456
    assert norm.src_ip == "192.168.1.10"
    assert norm.dst_ip == "192.168.1.20"
    assert norm.src_port == 12345
    assert norm.dst_port == 25
    assert norm.tcp_stream == 2
    assert norm.tcp_seq == 100
    assert norm.tcp_ack == 200
    assert norm.protocol_col == "SMTP"
    assert norm.plaintext_payload == "220 2.0.0 Ready\r\n"
    assert norm.tls_record_version == "0x0303"
    assert norm.tls_handshake_type == "1"
    assert norm.tls_supported_version == "0x0304"

def test_normalized_packet_malformed_fields():
    """Verify parser handles missing, malformed, or binary garbage payloads gracefully."""
    raw_packet = {
        "_source": {
            "layers": {
                "frame.number": ["invalid_number"],
                "tcp.payload": ["ffffffffffffffff"] # Non-printable binary
            }
        }
    }

    norm = parse_raw_packet_to_normalized(raw_packet)

    assert norm.frame_number == 0
    assert norm.timestamp == 0.0
    assert norm.src_ip == ""
    assert norm.tcp_seq is None
    assert norm.plaintext_payload is None # Binary payload rejected as plaintext

def test_security_event_model_creation_and_persistence(tmp_path):
    """Verify SecurityEvent database model persistence and Session relationship."""
    db_file = tmp_path / "test_stage_a.db"
    test_engine = create_engine(f"sqlite:///{db_file}")
    TestSessionLocal = sessionmaker(bind=test_engine)

    Base.metadata.create_all(bind=test_engine)
    db = TestSessionLocal()

    try:
        inv_id = f"inv_{uuid.uuid4().hex[:8]}"
        cap_id = f"cap_{uuid.uuid4().hex[:8]}"
        sess_id = f"sess_{uuid.uuid4().hex[:8]}"
        sec_evt_id = f"secevt_{uuid.uuid4().hex[:8]}"

        inv = Investigation(id=inv_id, title="Stage A Test Case")
        cap = Capture(id=cap_id, investigation_id=inv_id, filename="test.pcap", sha256="abc", bytes=100, format="pcap", stored_path="/tmp/test.pcap")
        sess = DbSessionModel(id=sess_id, capture_id=cap_id, tcp_stream=0, src="10.0.0.1", dst="10.0.0.2", src_port=50000, dst_port=25, protocol="SMTP")

        db.add_all([inv, cap, sess])
        db.commit()

        sec_evt = SecurityEvent(
            id=sec_evt_id,
            session_id=sess_id,
            event_type="UPGRADE_ACCEPTED",
            protocol="SMTP",
            upgrade_status="ACCEPTED",
            observed_value="220 2.0.0 Ready to start TLS",
            frame_numbers="10",
            timestamp="1700000000.123",
            evidence_source="TSHARK_REASSEMBLED_STREAM",
            completeness_status="COMPLETE",
            details_json=json.dumps({"command": "STARTTLS", "response_code": "220"})
        )
        db.add(sec_evt)
        db.commit()

        # Query back
        retrieved_sess = db.query(DbSessionModel).filter_by(id=sess_id).first()
        assert retrieved_sess is not None
        assert len(retrieved_sess.security_events) == 1
        
        evt = retrieved_sess.security_events[0]
        assert evt.id == sec_evt_id
        assert evt.event_type == "UPGRADE_ACCEPTED"
        assert evt.upgrade_status == "ACCEPTED"
        assert json.loads(evt.details_json)["command"] == "STARTTLS"
    finally:
        db.close()

def test_safe_database_migration(tmp_path):
    """Verify safe schema migration on existing database preserving prior records."""
    db_file = tmp_path / "legacy_stage.db"
    test_engine = create_engine(f"sqlite:///{db_file}")
    TestSessionLocal = sessionmaker(bind=test_engine)

    Base.metadata.create_all(bind=test_engine)
    db = TestSessionLocal()

    try:
        inv_id = "inv_legacy_01"
        inv = Investigation(id=inv_id, title="Pre-migration Case")
        db.add(inv)
        db.commit()

        # Run migration check
        ensure_schema_migrated(test_engine)

        # Confirm existing record is preserved intact
        existing_inv = db.query(Investigation).filter_by(id=inv_id).first()
        assert existing_inv is not None
        assert existing_inv.title == "Pre-migration Case"
    finally:
        db.close()
