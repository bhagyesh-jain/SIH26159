import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Any
from sqlalchemy.orm import Session as DbSession
from backend.app.models.database import Capture, AnalysisJob, Session, Event
from backend.app.services.tshark_adapter import extract_packets_json, TSharkAdapterError


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
    - 25, 465, 587 -> SMTP
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
    if ports & {25, 465, 587}:
        return "SMTP"
    if ports & {143, 993}:
        return "IMAP"
    if ports & {110, 995}:
        return "POP3"

    return "UNKNOWN"


def process_capture_streams(db: DbSession, capture_id: str, job_id: str):
    """
    Orchestrates capture stream extraction:
    1. Updates job status to PROCESSING
    2. Runs TShark CLI extraction
    3. Groups packets by tcp.stream
    4. Saves Sessions and Events in database
    5. Updates job status to COMPLETED (or FAILED)
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

        # Group packets by tcp.stream ID
        streams_map: Dict[int, List[Dict[str, Any]]] = {}

        for pkt in packets_raw:
            p_data = parse_packet_layers(pkt)
            s_id = p_data["stream_id"]
            if s_id is not None:
                if s_id not in streams_map:
                    streams_map[s_id] = []
                streams_map[s_id].append(p_data)

        # Create Session and Event database records
        for stream_id, packets in streams_map.items():
            if not packets:
                continue

            first_pkt = packets[0]
            src_ip = first_pkt["src_ip"]
            dst_ip = first_pkt["dst_ip"]
            src_port = first_pkt["src_port"]
            dst_port = first_pkt["dst_port"]

            observed_protos = [p["protocol"] for p in packets]
            protocol = classify_session_protocol(src_port, dst_port, observed_protos)

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

            for p_info in packets:
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
