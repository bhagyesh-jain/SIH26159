import binascii
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class NormalizedPacket:
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    tcp_stream: int
    tcp_seq: Optional[int]
    tcp_ack: Optional[int]
    protocol_col: str
    info_col: str
    tcp_payload_hex: Optional[str] = None
    plaintext_payload: Optional[str] = None
    tls_record_version: Optional[str] = None
    tls_handshake_type: Optional[str] = None
    tls_handshake_version: Optional[str] = None
    tls_supported_version: Optional[str] = None
    tls_ciphersuite: Optional[str] = None
    tls_alert_level: Optional[int] = None
    tls_alert_desc: Optional[int] = None

@dataclass
class NormalizedStream:
    tcp_stream: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: List[NormalizedPacket] = field(default_factory=list)

def _extract_single_val(layers: Dict[str, Any], key: str) -> str:
    val = layers.get(key)
    if isinstance(val, list) and len(val) > 0:
        return str(val[0])
    return str(val) if val is not None else ""

def parse_raw_packet_to_normalized(raw_packet: Dict[str, Any]) -> NormalizedPacket:
    """
    Parses a raw TShark JSON packet layer dictionary into a typed, normalized packet representation.
    Decodes TCP hex payload to plaintext strings when printable/unencrypted.
    """
    layers = raw_packet.get("_source", {}).get("layers", {})
    if not layers and "layers" in raw_packet:
        layers = raw_packet["layers"]

    frame_num_str = _extract_single_val(layers, "frame.number")
    time_epoch_str = _extract_single_val(layers, "frame.time_epoch")
    src_ip = _extract_single_val(layers, "ip.src") or _extract_single_val(layers, "ipv6.src")
    dst_ip = _extract_single_val(layers, "ip.dst") or _extract_single_val(layers, "ipv6.dst")
    src_port_str = _extract_single_val(layers, "tcp.srcport")
    dst_port_str = _extract_single_val(layers, "tcp.dstport")
    stream_str = _extract_single_val(layers, "tcp.stream")
    seq_str = _extract_single_val(layers, "tcp.seq")
    ack_str = _extract_single_val(layers, "tcp.ack")
    protocol_col = _extract_single_val(layers, "_ws.col.Protocol") or _extract_single_val(layers, "_ws.col.protocol")
    info_col = _extract_single_val(layers, "_ws.col.Info") or _extract_single_val(layers, "_ws.col.info")

    payload_hex = _extract_single_val(layers, "tcp.payload")
    plaintext = None
    if payload_hex:
        try:
            clean_hex = payload_hex.replace(":", "")
            raw_bytes = binascii.unhexlify(clean_hex)
            # Strict ASCII decode for protocol text commands/responses
            decoded = raw_bytes.decode("ascii", errors="strict")
            printable_count = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
            if len(decoded) > 0 and (printable_count / len(decoded)) > 0.85:
                plaintext = decoded
        except Exception:
            plaintext = None

    tls_rec_ver = _extract_single_val(layers, "tls.record.version") or None
    tls_hs_type = _extract_single_val(layers, "tls.handshake.type") or None
    tls_hs_ver = _extract_single_val(layers, "tls.handshake.version") or None
    tls_supp_ver = _extract_single_val(layers, "tls.handshake.extensions.supported_version") or None
    tls_cipher = _extract_single_val(layers, "tls.handshake.ciphersuite") or None

    alert_lvl_str = _extract_single_val(layers, "tls.alert_message.level")
    alert_desc_str = _extract_single_val(layers, "tls.alert_message.desc")

    return NormalizedPacket(
        frame_number=int(frame_num_str) if frame_num_str.isdigit() else 0,
        timestamp=float(time_epoch_str) if time_epoch_str.replace('.', '', 1).isdigit() else 0.0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(src_port_str) if src_port_str.isdigit() else 0,
        dst_port=int(dst_port_str) if dst_port_str.isdigit() else 0,
        tcp_stream=int(stream_str) if stream_str.isdigit() else 0,
        tcp_seq=int(seq_str) if seq_str.isdigit() else None,
        tcp_ack=int(ack_str) if ack_str.isdigit() else None,
        protocol_col=protocol_col,
        info_col=info_col,
        tcp_payload_hex=payload_hex if payload_hex else None,
        plaintext_payload=plaintext,
        tls_record_version=tls_rec_ver,
        tls_handshake_type=tls_hs_type,
        tls_handshake_version=tls_hs_ver,
        tls_supported_version=tls_supp_ver,
        tls_ciphersuite=tls_cipher,
        tls_alert_level=int(alert_lvl_str) if alert_lvl_str.isdigit() else None,
        tls_alert_desc=int(alert_desc_str) if alert_desc_str.isdigit() else None,
    )
