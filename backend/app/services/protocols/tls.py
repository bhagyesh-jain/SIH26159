import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from backend.app.schemas.normalized_packet import NormalizedPacket, NormalizedStream
from backend.app.services.protocols.base import UpgradeStatus, SecurityEventData

# Comprehensive mapping of TLS Cipher Suites
# Standard hex code / OpenSSL name / Key Exchange / PFS / AEAD / Cipher Mode
KNOWN_CIPHER_SUITES: Dict[str, Dict[str, Any]] = {
    # TLS 1.3 Cipher Suites (RFC 8446) - Mandatory Ephemeral Key Exchange (PFS) & AEAD
    "0x1301": {"name": "TLS_AES_128_GCM_SHA256", "kx": "ECDHE/DHE (TLS 1.3)", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0x1302": {"name": "TLS_AES_256_GCM_SHA384", "kx": "ECDHE/DHE (TLS 1.3)", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0x1303": {"name": "TLS_CHACHA20_POLY1305_SHA256", "kx": "ECDHE/DHE (TLS 1.3)", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0x1304": {"name": "TLS_AES_128_CCM_SHA256", "kx": "ECDHE/DHE (TLS 1.3)", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0x1305": {"name": "TLS_AES_128_CCM_8_SHA256", "kx": "ECDHE/DHE (TLS 1.3)", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},

    # TLS 1.2 ECDHE (Perfect Forward Secrecy) AEAD Cipher Suites
    "0xc030": {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kx": "ECDHE", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0xc02f": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kx": "ECDHE", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0xc02b": {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kx": "ECDHE", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0xc02c": {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "kx": "ECDHE", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},

    # TLS 1.2 DHE (Perfect Forward Secrecy) Cipher Suites
    "0x009e": {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kx": "DHE", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},
    "0x009f": {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "kx": "DHE", "pfs": "ENABLED", "mode": "AEAD", "security": "STRONG"},

    # Static RSA Key Exchange Cipher Suites (NO Perfect Forward Secrecy)
    "0x002f": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "CBC", "security": "WEAK_NO_PFS"},
    "0x0035": {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "CBC", "security": "WEAK_NO_PFS"},
    "0x003c": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA256", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "CBC", "security": "WEAK_NO_PFS"},
    "0x003d": {"name": "TLS_RSA_WITH_AES_256_CBC_SHA256", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "CBC", "security": "WEAK_NO_PFS"},
    "0x009c": {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "AEAD", "security": "WEAK_NO_PFS"},
    "0x009d": {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "AEAD", "security": "WEAK_NO_PFS"},
    "0x000a": {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kx": "STATIC_RSA", "pfs": "NO_PFS_STATIC_RSA", "mode": "CBC", "security": "VULNERABLE_SWEET32"},
}

def lookup_cipher_suite(cipher_val: str) -> Dict[str, Any]:
    """Normalizes and looks up a cipher suite by hex, decimal integer, or standard name."""
    if not cipher_val:
        return {"name": "UNKNOWN", "kx": "UNKNOWN", "pfs": "UNKNOWN", "mode": "UNKNOWN", "security": "UNKNOWN"}

    # Convert integer string to hex
    if isinstance(cipher_val, int) or cipher_val.isdigit():
        cipher_hex = f"0x{int(cipher_val):04x}"
    elif cipher_val.startswith("0x") or cipher_val.startswith("0X"):
        cipher_hex = cipher_val.lower()
    else:
        cipher_hex = cipher_val.lower()

    if cipher_hex in KNOWN_CIPHER_SUITES:
        return KNOWN_CIPHER_SUITES[cipher_hex]

    # Name-based matching fallback
    upper_name = cipher_val.upper()
    if "ECDHE" in upper_name:
        pfs = "ENABLED"
        kx = "ECDHE"
    elif "DHE" in upper_name or "EDH" in upper_name:
        pfs = "ENABLED"
        kx = "DHE"
    elif upper_name.startswith("TLS_RSA_") or "RSA" in upper_name and "ECDHE" not in upper_name and "DHE" not in upper_name:
        pfs = "NO_PFS_STATIC_RSA"
        kx = "STATIC_RSA"
    elif upper_name.startswith("TLS_AES_") or upper_name.startswith("TLS_CHACHA20_"):
        pfs = "ENABLED"
        kx = "ECDHE/DHE (TLS 1.3)"
    else:
        pfs = "UNKNOWN"
        kx = "UNKNOWN"

    mode = "AEAD" if ("GCM" in upper_name or "POLY1305" in upper_name or "CCM" in upper_name) else ("CBC" if "CBC" in upper_name else "UNKNOWN")
    security = "STRONG" if pfs == "ENABLED" else ("WEAK_NO_PFS" if pfs == "NO_PFS_STATIC_RSA" else "UNKNOWN")

    return {
        "name": cipher_val,
        "kx": kx,
        "pfs": pfs,
        "mode": mode,
        "security": security
    }

def normalize_tls_version(ver_val: Optional[str]) -> Optional[str]:
    """Normalizes version codes into standard version strings."""
    if not ver_val:
        return None
    val = ver_val.strip().lower()
    if val in ["0x0304", "0x304", "772", "tls 1.3", "tlsv1.3"]:
        return "TLSv1.3"
    elif val in ["0x0303", "0x303", "771", "tls 1.2", "tlsv1.2"]:
        return "TLSv1.2"
    elif val in ["0x0302", "0x302", "770", "tls 1.1", "tlsv1.1"]:
        return "TLSv1.1"
    elif val in ["0x0301", "0x301", "769", "tls 1.0", "tlsv1.0"]:
        return "TLSv1.0"
    elif val in ["0x0300", "0x300", "768", "ssl 3.0", "sslv3"]:
        return "SSLv3.0"
    return ver_val

@dataclass
class TLSAnalysisResult:
    protocol: str
    handshake_status: str  # "COMPLETED", "FAILED", "INTERRUPTED", "UNKNOWN"
    upgrade_status: UpgradeStatus
    tls_version_negotiated: Optional[str] = None
    selected_cipher_hex: Optional[str] = None
    selected_cipher_name: Optional[str] = None
    key_exchange: str = "UNKNOWN"
    forward_secrecy: str = "UNKNOWN"
    cipher_mode: str = "UNKNOWN"
    security_rating: str = "UNKNOWN"
    evidence_confidence: str = "UNKNOWN" # "OBSERVED_COMPLETION", "STRONGLY_SUPPORTED_COMPLETION", "FAILED", "UNKNOWN_OUTCOME"
    client_hello_frame: Optional[int] = None
    server_hello_frame: Optional[int] = None
    post_server_hello_records: int = 0
    tls_alert_level: Optional[str] = None
    tls_alert_desc: Optional[str] = None
    tcp_reset: bool = False
    evidence_source: str = "TSHARK_REASSEMBLED_STREAM"
    completeness_status: str = "COMPLETE"
    details: Dict[str, Any] = field(default_factory=dict)


def analyze_tls_stream(
    stream: NormalizedStream,
    protocol: str,
    upgrade_accepted: bool
) -> Tuple[TLSAnalysisResult, List[SecurityEventData]]:
    """
    Evidence-based TLS cryptographic analysis engine for SMTP, IMAP, and POP3 streams.
    Consumes a NormalizedStream and evaluates TLS handshake progression, version negotiation,
    selected cipher suites, key exchange mechanisms (PFS vs Static RSA), and observable alerts.
    """
    events: List[SecurityEventData] = []
    if not stream.packets:
        res = TLSAnalysisResult(protocol=protocol, handshake_status="UNKNOWN", upgrade_status=UpgradeStatus.UNKNOWN, evidence_confidence="UNKNOWN_OUTCOME")
        return res, events

    client_hello_frame: Optional[int] = None
    server_hello_frame: Optional[int] = None
    negotiated_ver: Optional[str] = None
    selected_cipher: Optional[str] = None
    key_share_observed: Optional[str] = None
    finished_msg_seen = False
    tls_alert_level: Optional[str] = None
    tls_alert_desc: Optional[str] = None
    has_fatal_alert = False
    has_tcp_reset = False
    post_server_hello_records = 0
    tls_frames: List[int] = []
    last_pkt_ts = stream.packets[-1].timestamp if stream.packets else 0.0

    for pkt in stream.packets:
        # Check for unencrypted TLS 1.2 Finished message (handshake type 20)
        if pkt.tls_handshake_type == "20" or "Finished" in (pkt.info_col or ""):
            finished_msg_seen = True

        # Check for KeyShare extension / group in info column or fields
        if "key_share" in (pkt.info_col or "").lower() or "x25519" in (pkt.info_col or "").lower():
            if "x25519" in (pkt.info_col or "").lower():
                key_share_observed = "X25519"
            else:
                key_share_observed = "KEY_SHARE_PRESENT"

        # 1. Parse ClientHello
        if pkt.tls_handshake_type == "1" or "Client Hello" in (pkt.info_col or ""):
            if not client_hello_frame:
                client_hello_frame = pkt.frame_number
            tls_frames.append(pkt.frame_number)

        # 2. Parse ServerHello & Disambiguate Negotiated TLS Version
        elif pkt.tls_handshake_type == "2" or pkt.tls_supported_version or "Server Hello" in (pkt.info_col or ""):
            if pkt.protocol_col in ["TLSv1.2", "TLSv1.3", "TLS", "SSL"] or "Server Hello" in (pkt.info_col or ""):
                if not server_hello_frame:
                    server_hello_frame = pkt.frame_number

                # Supported versions extension (0x0304 -> TLS 1.3 per RFC 8446) takes precedence
                if pkt.tls_supported_version:
                    negotiated_ver = normalize_tls_version(pkt.tls_supported_version)
                elif pkt.protocol_col == "TLSv1.3":
                    negotiated_ver = "TLSv1.3"
                elif pkt.protocol_col in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]:
                    negotiated_ver = normalize_tls_version(pkt.protocol_col)
                elif pkt.tls_record_version:
                    negotiated_ver = normalize_tls_version(pkt.tls_record_version)

                # Selected cipher suite from ServerHello
                if pkt.tls_ciphersuite:
                    selected_cipher = pkt.tls_ciphersuite

                tls_frames.append(pkt.frame_number)

        # 3. Track post-ServerHello record exchange
        if server_hello_frame and pkt.frame_number > server_hello_frame:
            if pkt.protocol_col in ["SSL", "TLS", "TLSv1.2", "TLSv1.3"] or pkt.tls_record_version:
                post_server_hello_records += 1
                tls_frames.append(pkt.frame_number)

        # 4. Check TCP Resets
        if "[RST" in (pkt.info_col or "") or "[RST]" in (pkt.info_col or ""):
            has_tcp_reset = True
            tls_frames.append(pkt.frame_number)

        # 5. Check TLS Alerts
        if pkt.tls_alert_level is not None or pkt.tls_alert_desc is not None or "Alert" in (pkt.info_col or ""):
            tls_alert_level = str(pkt.tls_alert_level) if pkt.tls_alert_level is not None else None
            tls_alert_desc = str(pkt.tls_alert_desc) if pkt.tls_alert_desc is not None else None
            if tls_alert_level == "2" or "Fatal" in (pkt.info_col or ""):
                has_fatal_alert = True
            tls_frames.append(pkt.frame_number)

    tls_frames = sorted(list(set(tls_frames)))

    # Cryptographic cipher assessment
    cipher_info = lookup_cipher_suite(selected_cipher or "")
    selected_cipher_name = cipher_info["name"]
    cipher_mode = cipher_info["mode"]
    security_rating = cipher_info["security"]

    # Key Exchange Determination (Refined Audit Requirement)
    if negotiated_ver == "TLSv1.3":
        forward_secrecy = "ENABLED"
        if key_share_observed:
            key_exchange = f"ECDHE/DHE ({key_share_observed})"
        else:
            key_exchange = "UNKNOWN"
    else:
        key_exchange = cipher_info["kx"]
        forward_secrecy = cipher_info["pfs"]

    # Determine Handshake Status & Evidence Confidence (Fatal alert / reset OVERRIDES all success flags)
    if not upgrade_accepted:
        handshake_status = "NOT_REQUESTED_OR_ACCEPTED"
        overall_upgrade_status = UpgradeStatus.UNKNOWN
        evidence_confidence = "UNKNOWN_OUTCOME"
    elif has_fatal_alert or (has_tcp_reset and post_server_hello_records == 0):
        handshake_status = "FAILED"
        overall_upgrade_status = UpgradeStatus.FAILED
        evidence_confidence = "FAILED"
    elif client_hello_frame and server_hello_frame and post_server_hello_records > 0 and not has_fatal_alert:
        handshake_status = "COMPLETED"
        overall_upgrade_status = UpgradeStatus.NEGOTIATED
        evidence_confidence = "OBSERVED_COMPLETION" if finished_msg_seen else "STRONGLY_SUPPORTED_COMPLETION"
    elif client_hello_frame and server_hello_frame and post_server_hello_records == 0:
        handshake_status = "UNKNOWN"
        overall_upgrade_status = UpgradeStatus.UNKNOWN
        evidence_confidence = "UNKNOWN_OUTCOME"
    elif client_hello_frame and not server_hello_frame:
        handshake_status = "FAILED"
        overall_upgrade_status = UpgradeStatus.FAILED
        evidence_confidence = "FAILED"
    else:
        handshake_status = "UNKNOWN"
        overall_upgrade_status = UpgradeStatus.UNKNOWN
        evidence_confidence = "UNKNOWN_OUTCOME"

    result = TLSAnalysisResult(
        protocol=protocol,
        handshake_status=handshake_status,
        upgrade_status=overall_upgrade_status,
        tls_version_negotiated=negotiated_ver,
        selected_cipher_hex=selected_cipher,
        selected_cipher_name=selected_cipher_name,
        key_exchange=key_exchange,
        forward_secrecy=forward_secrecy,
        cipher_mode=cipher_mode,
        security_rating=security_rating,
        evidence_confidence=evidence_confidence,
        client_hello_frame=client_hello_frame,
        server_hello_frame=server_hello_frame,
        post_server_hello_records=post_server_hello_records,
        tls_alert_level=tls_alert_level,
        tls_alert_desc=tls_alert_desc,
        tcp_reset=has_tcp_reset,
        details={
            "client_hello_seen": bool(client_hello_frame),
            "server_hello_seen": bool(server_hello_frame),
            "post_server_hello_records": post_server_hello_records,
            "evidence_confidence": evidence_confidence,
            "handshake_evidence": "CLIENT_SERVER_HELLO_AND_POST_HANDSHAKE_RECORD_EXCHANGE" if handshake_status == "COMPLETED" else "INCOMPLETE_OR_FAILED",
            "encrypted_cert_note": "Server certificate encrypted under TLS 1.3 handshake keys (passive access unavailable without keylogs)" if negotiated_ver == "TLSv1.3" else "Server certificate visible in TLS 1.2 handshake",
            "alert_limitation_note": f"Observable TLS alert level {tls_alert_level}, code {tls_alert_desc} recorded from frame" if tls_alert_level else None
        }
    )


    # Emit Security Events
    if overall_upgrade_status == UpgradeStatus.FAILED:
        events.append(
            SecurityEventData(
                event_type="HANDSHAKE_FAILED",
                protocol=protocol,
                observed_value="TLS_HANDSHAKE_ABORTED_OR_FAILED",
                frame_numbers=tls_frames if tls_frames else [stream.packets[-1].frame_number],
                timestamp=last_pkt_ts,
                upgrade_status=UpgradeStatus.FAILED,
                details={
                    "client_hello_seen": bool(client_hello_frame),
                    "server_hello_seen": bool(server_hello_frame),
                    "alert_level": tls_alert_level,
                    "alert_desc": tls_alert_desc,
                    "tcp_reset": has_tcp_reset,
                    "reason": "FATAL_TLS_ALERT_OR_PREMATURE_TCP_RESET"
                }
            )
        )
    elif overall_upgrade_status == UpgradeStatus.NEGOTIATED:
        events.append(
            SecurityEventData(
                event_type="TLS_NEGOTIATED",
                protocol=protocol,
                observed_value=f"TLS_HANDSHAKE_SUCCESSFUL_{negotiated_ver or 'TLS'}",
                frame_numbers=tls_frames,
                timestamp=last_pkt_ts,
                upgrade_status=UpgradeStatus.NEGOTIATED,
                details={
                    "tls_version": negotiated_ver,
                    "selected_cipher": selected_cipher_name,
                    "cipher_hex": selected_cipher,
                    "key_exchange": key_exchange,
                    "forward_secrecy": forward_secrecy,
                    "cipher_mode": cipher_mode,
                    "handshake_completed": True
                }
            )
        )
        # Emit Cryptographic Assessment Event
        events.append(
            SecurityEventData(
                event_type="TLS_CRYPTOGRAPHIC_ASSESSMENT",
                protocol=protocol,
                observed_value=f"{negotiated_ver}_{selected_cipher_name}",
                frame_numbers=tls_frames,
                timestamp=last_pkt_ts,
                upgrade_status=UpgradeStatus.NEGOTIATED,
                details={
                    "tls_version": negotiated_ver,
                    "selected_cipher_name": selected_cipher_name,
                    "selected_cipher_hex": selected_cipher,
                    "key_exchange": key_exchange,
                    "forward_secrecy": forward_secrecy,
                    "cipher_mode": cipher_mode,
                    "security_rating": security_rating,
                    "encrypted_cert_note": result.details.get("encrypted_cert_note")
                }
            )
        )
    elif handshake_status == "UNKNOWN" and client_hello_frame and server_hello_frame:
        events.append(
            SecurityEventData(
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
        )

    return result, events
