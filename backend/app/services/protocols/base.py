import json
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream

class UpgradeStatus(str, Enum):
    NOT_OFFERED = "NOT_OFFERED"
    OFFERED_NOT_USED = "OFFERED_NOT_USED"
    REQUESTED = "REQUESTED"
    ACCEPTED = "ACCEPTED"
    NEGOTIATED = "NEGOTIATED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

@dataclass
class SecurityEventData:
    event_type: str
    protocol: str
    observed_value: str
    frame_numbers: List[int]
    timestamp: float
    upgrade_status: Optional[UpgradeStatus] = None
    evidence_source: str = "TSHARK_REASSEMBLED_STREAM"
    completeness_status: str = "COMPLETE"
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class StreamLine:
    direction: str  # "C2S" or "S2C"
    line: str
    frame_numbers: List[int]
    timestamp: float

KNOWN_SERVER_PORTS = {25, 465, 587, 2525, 2526, 2527, 2528, 143, 993, 110, 995}

def reassemble_stream_lines(stream: NormalizedStream) -> List[StreamLine]:
    """
    Reassembles plaintext line-oriented protocol commands/responses from a NormalizedStream.
    Handles TCP segmentation, duplicate sequence filtering (retransmissions), multi-command
    segments, and attributes exact frame numbers to each line.
    """
    if not stream.packets:
        return []

    # 1. Identify Server Endpoint
    server_port = stream.dst_port
    if stream.src_port in KNOWN_SERVER_PORTS and stream.dst_port not in KNOWN_SERVER_PORTS:
        server_port = stream.src_port

    # Group packets by direction
    c2s_packets: List[NormalizedPacket] = []
    s2c_packets: List[NormalizedPacket] = []

    for pkt in stream.packets:
        if pkt.dst_port == server_port:
            c2s_packets.append(pkt)
        else:
            s2c_packets.append(pkt)

    # Reassemble lines per direction
    reassembled_lines: List[StreamLine] = []

    for direction, packets in [("C2S", c2s_packets), ("S2C", s2c_packets)]:
        # Deduplicate retransmissions using (tcp_seq, payload_length)
        seen_seqs = set()
        unique_packets: List[NormalizedPacket] = []
        for pkt in sorted(packets, key=lambda p: p.frame_number):
            if pkt.tcp_payload_hex and pkt.tcp_seq is not None:
                seq_key = (pkt.tcp_seq, len(pkt.tcp_payload_hex))
                if seq_key in seen_seqs:
                    continue
                seen_seqs.add(seq_key)
            unique_packets.append(pkt)

        buffer = ""
        current_frames: List[int] = []
        last_ts = 0.0

        for pkt in unique_packets:
            if not pkt.plaintext_payload:
                continue
            
            payload = pkt.plaintext_payload
            last_ts = pkt.timestamp
            
            # Walk payload characters to build lines
            start_idx = 0
            while start_idx < len(payload):
                newline_pos = payload.find("\n", start_idx)
                if newline_pos != -1:
                    segment = payload[start_idx:newline_pos + 1]
                    buffer += segment
                    if pkt.frame_number not in current_frames:
                        current_frames.append(pkt.frame_number)
                    
                    # Clean line
                    clean_line = buffer.rstrip("\r\n")
                    if clean_line:
                        reassembled_lines.append(
                            StreamLine(
                                direction=direction,
                                line=clean_line,
                                frame_numbers=list(current_frames),
                                timestamp=last_ts
                            )
                        )
                    buffer = ""
                    current_frames = []
                    start_idx = newline_pos + 1
                else:
                    # Partial line chunk in segment
                    buffer += payload[start_idx:]
                    if pkt.frame_number not in current_frames:
                        current_frames.append(pkt.frame_number)
                    break

        # Handle remaining buffer if capture truncated mid-line
        if buffer.strip():
            reassembled_lines.append(
                StreamLine(
                    direction=direction,
                    line=buffer.rstrip("\r\n"),
                    frame_numbers=list(current_frames),
                    timestamp=last_ts
                )
            )

    # Sort all reassembled lines chronologically by earliest frame number
    reassembled_lines.sort(key=lambda l: l.frame_numbers[0] if l.frame_numbers else 0)
    return reassembled_lines


def evaluate_tls_handshake(
    stream: NormalizedStream,
    protocol: str,
    upgrade_accepted: bool
) -> Tuple[UpgradeStatus, Optional[SecurityEventData]]:
    """
    Strengthened passive TLS handshake evaluator across SMTP, IMAP, and POP3 streams.
    Does NOT treat ClientHello + ServerHello alone as proof of completed negotiation.
    
    Distinguishes:
    - HANDSHAKE_INITIATED (ClientHello seen)
    - SERVER_PARAMETERS_SELECTED (ServerHello seen)
    - HANDSHAKE_COMPLETED (ClientHello + ServerHello + post-ServerHello record exchange without fatal alert)
    - HANDSHAKE_FAILED (Fatal TLS alert, TCP reset during handshake, or missing ServerHello)
    - HANDSHAKE_OUTCOME_UNKNOWN (Truncated stream after ServerHello without post-handshake evidence)
    
    For TLS 1.3:
    Handshake messages following ServerHello (EncryptedExtensions, Certificate, Finished)
    are encrypted under handshake keys. A passive observer without keylogs cannot inspect
    the decrypted Finished record, but CAN establish completion via post-ServerHello
    record exchange and absence of fatal alerts or TCP resets.
    """
    if not upgrade_accepted or not stream.packets:
        return UpgradeStatus.UNKNOWN, None

    tls_client_hello = False
    tls_server_hello = False
    server_hello_frame: Optional[int] = None
    tls_alert_level: Optional[Any] = None
    tls_alert_desc: Optional[Any] = None
    has_fatal_alert = False
    has_tcp_reset = False
    post_server_hello_records = 0
    tls_frames: List[int] = []
    last_pkt_ts = stream.packets[-1].timestamp if stream.packets else 0.0

    for pkt in stream.packets:
        # Check ClientHello (handshake type 1)
        if pkt.tls_handshake_type == "1" or "Client Hello" in (pkt.info_col or ""):
            tls_client_hello = True
            tls_frames.append(pkt.frame_number)

        # Check ServerHello (handshake type 2 or supported version field)
        elif pkt.tls_handshake_type == "2" or pkt.tls_supported_version or "Server Hello" in (pkt.info_col or ""):
            if pkt.protocol_col in ["TLSv1.2", "TLSv1.3", "TLS", "SSL"] or "Server Hello" in (pkt.info_col or ""):
                tls_server_hello = True
                server_hello_frame = pkt.frame_number
                tls_frames.append(pkt.frame_number)

        # Track records after ServerHello
        if tls_server_hello and pkt.frame_number > (server_hello_frame or 0):
            if pkt.protocol_col in ["SSL", "TLS", "TLSv1.2", "TLSv1.3"] or pkt.tls_record_version:
                post_server_hello_records += 1
                tls_frames.append(pkt.frame_number)

        # Check TCP resets
        if "[RST" in (pkt.info_col or "") or "[RST]" in (pkt.info_col or ""):
            has_tcp_reset = True
            tls_frames.append(pkt.frame_number)

        # Check TLS Alerts
        if pkt.tls_alert_level is not None or pkt.tls_alert_desc is not None or "Alert" in (pkt.info_col or ""):
            tls_alert_level = pkt.tls_alert_level
            tls_alert_desc = pkt.tls_alert_desc
            if str(pkt.tls_alert_level) == "2" or "Fatal" in (pkt.info_col or ""):
                has_fatal_alert = True
            tls_frames.append(pkt.frame_number)

    tls_frames = sorted(list(set(tls_frames)))

    # Classification logic
    if has_fatal_alert or (has_tcp_reset and post_server_hello_records == 0):
        # Explicit handshake failure
        event = SecurityEventData(
            event_type="HANDSHAKE_FAILED",
            protocol=protocol,
            observed_value="TLS_HANDSHAKE_ABORTED_OR_FAILED",
            frame_numbers=tls_frames if tls_frames else [stream.packets[-1].frame_number],
            timestamp=last_pkt_ts,
            upgrade_status=UpgradeStatus.FAILED,
            details={
                "client_hello_seen": tls_client_hello,
                "server_hello_seen": tls_server_hello,
                "alert_level": tls_alert_level,
                "alert_desc": tls_alert_desc,
                "tcp_reset": has_tcp_reset,
                "reason": "FATAL_TLS_ALERT_OR_PREMATURE_TCP_RESET"
            }
        )
        return UpgradeStatus.FAILED, event

    elif tls_client_hello and tls_server_hello and post_server_hello_records > 0 and not has_fatal_alert:
        # Handshake completion supported by empirical post-ServerHello record exchange evidence
        event = SecurityEventData(
            event_type="TLS_NEGOTIATED",
            protocol=protocol,
            observed_value="TLS_HANDSHAKE_SUCCESSFUL",
            frame_numbers=tls_frames,
            timestamp=last_pkt_ts,
            upgrade_status=UpgradeStatus.NEGOTIATED,
            details={
                "client_hello_seen": True,
                "server_hello_seen": True,
                "post_server_hello_records": post_server_hello_records,
                "handshake_evidence": "CLIENT_SERVER_HELLO_AND_POST_HANDSHAKE_RECORD_EXCHANGE",
                "tls_13_note": "Post-ServerHello handshake messages encrypted per TLS 1.3 spec"
            }
        )
        return UpgradeStatus.NEGOTIATED, event

    elif tls_client_hello and tls_server_hello and post_server_hello_records == 0:
        # ServerHello received but no post-ServerHello records seen
        event = SecurityEventData(
            event_type="HANDSHAKE_OUTCOME_UNKNOWN",
            protocol=protocol,
            observed_value="SERVER_HELLO_SEEN_BUT_NO_POST_HANDSHAKE_DATA",
            frame_numbers=tls_frames,
            timestamp=last_pkt_ts,
            upgrade_status=UpgradeStatus.UNKNOWN,
            details={
                "client_hello_seen": True,
                "server_hello_seen": True,
                "post_server_hello_records": 0,
                "reason": "STREAM_TRUNCATED_AFTER_SERVER_HELLO"
            }
        )
        return UpgradeStatus.UNKNOWN, event

    elif tls_client_hello and not tls_server_hello:
        # ClientHello sent but no ServerHello received
        event = SecurityEventData(
            event_type="HANDSHAKE_FAILED",
            protocol=protocol,
            observed_value="CLIENT_HELLO_SENT_NO_SERVER_RESPONSE",
            frame_numbers=tls_frames,
            timestamp=last_pkt_ts,
            upgrade_status=UpgradeStatus.FAILED,
            details={
                "client_hello_seen": True,
                "server_hello_seen": False,
                "reason": "SERVER_DID_NOT_RESPOND_TO_CLIENT_HELLO"
            }
        )
        return UpgradeStatus.FAILED, event

    return UpgradeStatus.UNKNOWN, None

