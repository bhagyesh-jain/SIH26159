import json
import uuid
import datetime
import re
from pathlib import Path
from typing import Dict, List, Any
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import Capture, AnalysisJob, Session, Event, SecurityEvent
from backend.app.services.tshark_adapter import extract_packets_json, TSharkAdapterError
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream, parse_raw_packet_to_normalized
from backend.app.services.protocols.base import UpgradeStatus, SecurityEventData
from backend.app.services.protocols.smtp import SMTPStateMachine
from backend.app.services.protocols.imap import IMAPStateMachine
from backend.app.services.protocols.pop3 import POP3StateMachine
from backend.app.services.protocols.tls import analyze_tls_stream


def parse_packet_layers(packet: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts simplified key-values from TShark's JSON packet representation."""
    layers = packet.get("_source", {}).get("layers", {})

    def _get_val(key: str) -> str:
        val = layers.get(key)
        if isinstance(val, list) and len(val) > 0:
            return str(val[0])
        return str(val) if val is not None else ""

    frame_num = _get_val("frame.number")
    time_epoch = _get_val("frame.time_epoch")
    src_ip = _get_val("ip.src") or _get_val("ipv6.src")
    dst_ip = _get_val("ip.dst") or _get_val("ipv6.dst")
    src_port = _get_val("tcp.srcport")
    dst_port = _get_val("tcp.dstport")
    stream_id = _get_val("tcp.stream")
    protocol = _get_val("_ws.col.Protocol")
    info = _get_val("_ws.col.Info")

    return {
        "frame_number": int(frame_num) if frame_num.isdigit() else 0,
        "time_epoch": time_epoch,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port) if src_port.isdigit() else 0,
        "dst_port": int(dst_port) if dst_port.isdigit() else 0,
        "stream_id": int(stream_id) if stream_id.isdigit() else None,
        "protocol": protocol,
        "info": info,
    }


def classify_session_protocol(src_port: int, dst_port: int, raw_protocols: List[str]) -> str:
    """
    Classifies session protocol based on observed TShark protocol labels and standard email ports.
    - 25, 465, 587, 2525-2528 -> SMTP
    - 143, 993 -> IMAP
    - 110, 995 -> POP3
    """
    proto_set = {p.upper() for p in raw_protocols if p}

    if "SMTP" in proto_set or "ESMTP" in proto_set:
        return "SMTP"
    if "IMAP" in proto_set or "IMAP4" in proto_set:
        return "IMAP"
    if "POP" in proto_set or "POP3" in proto_set:
        return "POP3"

    ports = {src_port, dst_port}
    if ports & {25, 465, 587, 2525, 2526, 2527, 2528}:
        return "SMTP"
    if ports & {143, 993}:
        return "IMAP"
    if ports & {110, 995}:
        return "POP3"

    return "UNKNOWN"


def _sanitize_sensitive_data(val: str) -> str:
    """Redacts passwords and sensitive auth tokens from string data."""
    if not val:
        return val
    # Redact IMAP LOGIN <user> <pass>
    val = re.sub(r'(\bLOGIN\s+\S+\s+)(\S+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)
    # Redact POP3 PASS <pass>
    val = re.sub(r'(\bPASS\s+)(\S+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)
    # Redact SMTP AUTH PLAIN/LOGIN payload tokens
    val = re.sub(r'(\bAUTH\s+(?:PLAIN|LOGIN)\s+)(\S+)', r'\1[REDACTED]', val, flags=re.IGNORECASE)
    return val


def process_capture_streams(db: DbSession, capture_id: str, job_id: str):
    """
    Orchestrates capture stream extraction:
    1. Updates job status to PROCESSING
    2. Runs TShark CLI extraction
    3. Groups packets by tcp.stream
    4. Runs protocol detection state machines and TLS cryptographic analysis
    5. Persists Sessions, Events, and evidence-backed SecurityEvents in database
    6. Updates job status to COMPLETED (or FAILED)
    """
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    capture = db.query(Capture).filter(Capture.id == capture_id).first()

    if not job or not capture:
        return

    job.state = "PROCESSING"
    job.started_at = datetime.datetime.utcnow()
    db.commit()

    try:
        pcap_path = Path(capture.stored_path)
        packets_raw = extract_packets_json(pcap_path)

        # Clear existing sessions for re-analysis idempotency
        existing_sessions = db.query(Session).filter(Session.capture_id == capture_id).all()
        for s in existing_sessions:
            db.delete(s)
        db.flush()

        # Parse normalized packets
        normalized_packets: List[NormalizedPacket] = [
            parse_raw_packet_to_normalized(pkt) for pkt in packets_raw
        ]

        # Group packets by stream_id
        streams_map: Dict[int, List[NormalizedPacket]] = {}
        raw_layers_map: Dict[int, List[Dict[str, Any]]] = {}

        for raw_pkt, norm_pkt in zip(packets_raw, normalized_packets):
            s_id = norm_pkt.tcp_stream
            if s_id is not None:
                if s_id not in streams_map:
                    streams_map[s_id] = []
                    raw_layers_map[s_id] = []
                streams_map[s_id].append(norm_pkt)
                raw_layers_map[s_id].append(parse_packet_layers(raw_pkt))

        for stream_id, norm_pkts in streams_map.items():
            if not norm_pkts:
                continue

            first_pkt = norm_pkts[0]
            src_ip = first_pkt.src_ip
            dst_ip = first_pkt.dst_ip
            src_port = first_pkt.src_port
            dst_port = first_pkt.dst_port

            observed_protos = [p.protocol_col for p in norm_pkts if p.protocol_col]
            protocol = classify_session_protocol(src_port, dst_port, observed_protos)

            norm_stream = NormalizedStream(
                tcp_stream=stream_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packets=norm_pkts
            )

            session_db_id = f"sess_{uuid.uuid4().hex[:12]}"
            db_session_rec = Session(
                id=session_db_id,
                capture_id=capture_id,
                tcp_stream=stream_id,
                src=src_ip,
                dst=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                completeness="COMPLETE",
            )
            db.add(db_session_rec)
            db.flush()

            # Create Event database records for packet timeline
            raw_pkts_info = raw_layers_map[stream_id]
            for p_info in raw_pkts_info:
                event_db_id = f"evt_{uuid.uuid4().hex[:12]}"
                db_event = Event(
                    id=event_db_id,
                    session_id=session_db_id,
                    packet_number=p_info["frame_number"],
                    event_type="PACKET",
                    timestamp=p_info["time_epoch"],
                    observed_json=json.dumps(p_info),
                )
                db.add(db_event)

            # Protocol State Machine & TLS Detection Engine
            sec_events: List[SecurityEventData] = []
            if protocol == "SMTP":
                sm = SMTPStateMachine()
                sec_events = sm.analyze_stream(norm_stream)
            elif protocol == "IMAP":
                sm = IMAPStateMachine()
                sec_events = sm.analyze_stream(norm_stream)
            elif protocol == "POP3":
                sm = POP3StateMachine()
                sec_events = sm.analyze_stream(norm_stream)
            else:
                # UNKNOWN protocol fallback state machine evaluation
                for sm_cls in [SMTPStateMachine, IMAPStateMachine, POP3StateMachine]:
                    test_events = sm_cls().analyze_stream(norm_stream)
                    if test_events:
                        sec_events = test_events
                        break

            # Fallback for implicit TLS or non-STARTTLS TLS handshakes
            has_tls_negotiated_evt = any(
                e.event_type in ["TLS_NEGOTIATED", "HANDSHAKE_FAILED", "HANDSHAKE_OUTCOME_UNKNOWN"]
                for e in sec_events
            )
            if not has_tls_negotiated_evt:
                has_client_hello = any(
                    p.tls_handshake_type == "1" or "Client Hello" in (p.info_col or "")
                    for p in norm_pkts
                )
                if has_client_hello or (src_port in {465, 993, 995} or dst_port in {465, 993, 995}):
                    _, tls_evts = analyze_tls_stream(norm_stream, protocol, upgrade_accepted=True)
                    sec_events.extend(tls_evts)

            # Persist SecurityEvent records
            for evt in sec_events:
                sec_db_id = f"sevt_{uuid.uuid4().hex[:12]}"
                frame_strs = ",".join(str(f) for f in evt.frame_numbers) if evt.frame_numbers else ""

                # Sanitize observed value & details for sensitive auth data
                clean_obs_val = _sanitize_sensitive_data(evt.observed_value)
                clean_details = evt.details or {}
                if isinstance(clean_details, dict):
                    # Redact any values inside details dictionary
                    clean_details = {
                        k: (_sanitize_sensitive_data(str(v)) if isinstance(v, str) else v)
                        for k, v in clean_details.items()
                    }

                up_status_val = evt.upgrade_status.value if isinstance(evt.upgrade_status, UpgradeStatus) else evt.upgrade_status

                db_sec_event = SecurityEvent(
                    id=sec_db_id,
                    session_id=session_db_id,
                    event_type=evt.event_type,
                    protocol=evt.protocol,
                    upgrade_status=up_status_val,
                    observed_value=clean_obs_val,
                    frame_numbers=frame_strs,
                    timestamp=str(evt.timestamp) if evt.timestamp is not None else None,
                    evidence_source=evt.evidence_source,
                    completeness_status=evt.completeness_status,
                    details_json=json.dumps(clean_details) if clean_details else None
                )
                db.add(db_sec_event)

        job.state = "COMPLETED"
        job.ended_at = datetime.datetime.utcnow()
        db.commit()

    except TSharkAdapterError as err:
        job.state = "FAILED"
        job.error_code = str(err)
        job.ended_at = datetime.datetime.utcnow()
        db.commit()
    except Exception as err:
        job.state = "FAILED"
        job.error_code = f"Unexpected processing error: {str(err)}"
        job.ended_at = datetime.datetime.utcnow()
        db.commit()
