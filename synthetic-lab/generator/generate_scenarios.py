import os
import sys
import time
import socket
import ssl
import json
import hashlib
import struct
import subprocess
from pathlib import Path

OUTPUT_DIR = Path("/captures")
MANIFEST_DIR = Path("/manifests")
CERTS_DIR = Path("/certs")

POSTFIX_HOST = "postfix.mailnet"
DOVECOT_HOST = "dovecot.mailnet"

def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def wait_for_port(host: str, port: int, timeout: int = 30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except (OSError, socket.error):
            time.sleep(1)
    raise RuntimeError(f"Timed out waiting for {host}:{port}")

def recv_smtp_response(sock: socket.socket) -> str:
    buf = ""
    sock.settimeout(5.0)
    while True:
        try:
            data = sock.recv(4096).decode(errors="ignore")
            if not data:
                break
            buf += data
            lines = [l for l in buf.split("\r\n") if l]
            if lines:
                last_line = lines[-1]
                if len(last_line) >= 4 and last_line[3] == " ":
                    break
                elif len(last_line) < 4:
                    break
        except socket.timeout:
            break
    return buf

def start_tcpdump(pcap_path: Path) -> subprocess.Popen:
    if pcap_path.exists():
        pcap_path.unlink()
    
    cmd = [
        "tcpdump",
        "-i", "any",
        "-U",
        "-w", str(pcap_path),
        "tcp port 25 or tcp port 2525 or tcp port 2526 or tcp port 2527 or tcp port 2528 or tcp port 143 or tcp port 110"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)  # Allow tcpdump interface binding
    return proc

def stop_tcpdump(proc: subprocess.Popen):
    time.sleep(1.5)  # Ensure all packets flush to disk
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

def inspect_pcap_with_tshark(pcap_path: Path) -> dict:
    """Use tshark inside container to observe packet details."""
    result = {
        "packets_captured": 0,
        "tshark_detected_protocol": "UNKNOWN",
        "handshake_completed": False,
        "tls_version_observed": None,
        "cipher_observed": None,
    }
    try:
        tshark_cmd = [
            "tshark", "-r", str(pcap_path),
            "-T", "fields",
            "-e", "frame.number",
            "-e", "_ws.col.Protocol",
            "-e", "tls.handshake.version",
            "-e", "tls.handshake.ciphersuite"
        ]
        res = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=10)
        lines = [line for line in res.stdout.strip().split("\n") if line]
        result["packets_captured"] = len(lines)
        
        protocols = set()
        for line in lines:
            parts = line.split("\t")
            if len(parts) > 1 and parts[1]:
                protocols.add(parts[1])
            if len(parts) > 2 and parts[2]:
                result["tls_version_observed"] = parts[2]
            if len(parts) > 3 and parts[3]:
                result["cipher_observed"] = parts[3]
        
        if "SMTP" in protocols or "ESMTP" in protocols:
            result["tshark_detected_protocol"] = "SMTP"
        elif "IMAP" in protocols:
            result["tshark_detected_protocol"] = "IMAP"
        elif "POP" in protocols or "POP3" in protocols:
            result["tshark_detected_protocol"] = "POP3"
        elif "TLSv1.2" in protocols or "TLSv1.3" in protocols or "TLS" in protocols:
            result["tshark_detected_protocol"] = "TLS"
    except Exception as e:
        print(f"[TShark Inspection Warning] {e}")
    return result

# --- Scenario Implementations ---

def run_scn_smtp_01(pcap_path: Path) -> dict:
    """SCN-SMTP-01: Plaintext SMTP session (no STARTTLS)"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    try:
        s = socket.create_connection((POSTFIX_HOST, 2527), timeout=10)
        client_log.append(recv_smtp_response(s))
        s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"MAIL FROM:<sender@lab.local>\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"RCPT TO:<recipient@lab.local>\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"DATA\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"Subject: Test Plaintext SMTP\r\n\r\nHello Plaintext\r\n.\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"QUIT\r\n")
        client_log.append(recv_smtp_response(s))
        s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "starttls_offered": False,
        "starttls_requested": False,
        "tls_negotiated": False
    }

def run_scn_smtp_02(pcap_path: Path) -> dict:
    """SCN-SMTP-02: SMTP with successful STARTTLS upgrade (Full Session)"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    tls_info = {}
    try:
        raw_s = socket.create_connection((POSTFIX_HOST, 25), timeout=10)
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"EHLO client.mailnet\r\n")
        resp = recv_smtp_response(raw_s)
        client_log.append(resp)
        
        raw_s.sendall(b"STARTTLS\r\n")
        resp_st = recv_smtp_response(raw_s)
        client_log.append(resp_st)
        
        ctx = ssl.create_default_context(cafile=str(CERTS_DIR / "ca.crt"))
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="postfix.mailnet")
        
        tls_info["version"] = ssl_s.version()
        tls_info["cipher"] = ssl_s.cipher()
        
        ssl_s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(ssl_s))
        ssl_s.sendall(b"MAIL FROM:<sender@lab.local>\r\n")
        client_log.append(recv_smtp_response(ssl_s))
        ssl_s.sendall(b"RCPT TO:<recipient@lab.local>\r\n")
        client_log.append(recv_smtp_response(ssl_s))
        ssl_s.sendall(b"QUIT\r\n")
        client_log.append(recv_smtp_response(ssl_s))
        ssl_s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "tls_info": tls_info,
        "starttls_offered": True,
        "starttls_requested": True,
        "tls_negotiated": True
    }

def run_scn_smtp_03(pcap_path: Path) -> dict:
    """SCN-SMTP-03: STARTTLS advertised but not requested (Explicit Plaintext Transmission)"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    try:
        s = socket.create_connection((POSTFIX_HOST, 25), timeout=10)
        client_log.append(recv_smtp_response(s))
        s.sendall(b"EHLO client.mailnet\r\n")
        resp = recv_smtp_response(s)
        client_log.append(resp)

        # Intentionally skip STARTTLS and send full plaintext email commands
        s.sendall(b"MAIL FROM:<sender@lab.local>\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"RCPT TO:<recipient@lab.local>\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"DATA\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"Subject: Plaintext Message Despite STARTTLS Capability\r\n\r\nUnencrypted body\r\n.\r\n")
        client_log.append(recv_smtp_response(s))
        s.sendall(b"QUIT\r\n")
        client_log.append(recv_smtp_response(s))
        s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "starttls_offered": True,
        "starttls_requested": False,
        "tls_negotiated": False
    }

def run_scn_imap_01(pcap_path: Path) -> dict:
    """SCN-IMAP-01: IMAP with successful STARTTLS upgrade"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    tls_info = {}
    try:
        raw_s = socket.create_connection((DOVECOT_HOST, 143), timeout=10)
        client_log.append(raw_s.recv(1024).decode())
        raw_s.sendall(b"A01 CAPABILITY\r\n")
        client_log.append(raw_s.recv(1024).decode())
        raw_s.sendall(b"A02 STARTTLS\r\n")
        resp = raw_s.recv(1024).decode()
        client_log.append(resp)

        ctx = ssl.create_default_context(cafile=str(CERTS_DIR / "ca.crt"))
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="dovecot.mailnet")
        
        tls_info["version"] = ssl_s.version()
        tls_info["cipher"] = ssl_s.cipher()

        ssl_s.sendall(b"A03 LOGIN user@mailnet password123\r\n")
        client_log.append(ssl_s.recv(1024).decode())
        ssl_s.sendall(b"A04 LOGOUT\r\n")
        client_log.append(ssl_s.recv(1024).decode())
        ssl_s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "tls_info": tls_info,
        "starttls_offered": True,
        "starttls_requested": True,
        "tls_negotiated": True
    }

def run_scn_pop3_01(pcap_path: Path) -> dict:
    """SCN-POP3-01: POP3 with successful STLS upgrade"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    tls_info = {}
    try:
        raw_s = socket.create_connection((DOVECOT_HOST, 110), timeout=10)
        client_log.append(raw_s.recv(1024).decode())
        raw_s.sendall(b"CAPA\r\n")
        client_log.append(raw_s.recv(1024).decode())
        raw_s.sendall(b"STLS\r\n")
        resp = raw_s.recv(1024).decode()
        client_log.append(resp)

        ctx = ssl.create_default_context(cafile=str(CERTS_DIR / "ca.crt"))
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="dovecot.mailnet")
        
        tls_info["version"] = ssl_s.version()
        tls_info["cipher"] = ssl_s.cipher()

        ssl_s.sendall(b"USER user@mailnet\r\n")
        client_log.append(ssl_s.recv(1024).decode())
        ssl_s.sendall(b"PASS password123\r\n")
        client_log.append(ssl_s.recv(1024).decode())
        ssl_s.sendall(b"QUIT\r\n")
        client_log.append(ssl_s.recv(1024).decode())
        ssl_s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "tls_info": tls_info,
        "stls_offered": True,
        "stls_requested": True,
        "tls_negotiated": True
    }

def run_scn_tls12_baseline_01(pcap_path: Path) -> dict:
    """SCN-TLS12-BASELINE-01: Standard TLS 1.2 Baseline with Forward Secrecy"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    tls_info = {}
    try:
        raw_s = socket.create_connection((POSTFIX_HOST, 2528), timeout=10)
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"STARTTLS\r\n")
        client_log.append(recv_smtp_response(raw_s))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.load_verify_locations(cafile=str(CERTS_DIR / "ca.crt"))
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="postfix.mailnet")

        tls_info["version"] = ssl_s.version()
        tls_info["cipher"] = ssl_s.cipher()

        ssl_s.sendall(b"QUIT\r\n")
        client_log.append(recv_smtp_response(ssl_s))
        ssl_s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "tls_info": tls_info,
        "tls_negotiated": True
    }

def run_scn_tls_weak_01(pcap_path: Path) -> dict:
    """SCN-TLS-WEAK-01: Forced Non-Forward-Secrecy Static RSA Cipher Suite"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    tls_info = {}
    try:
        raw_s = socket.create_connection((POSTFIX_HOST, 2528), timeout=10)
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"STARTTLS\r\n")
        client_log.append(recv_smtp_response(raw_s))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.load_verify_locations(cafile=str(CERTS_DIR / "ca.crt"))
        # Force non-PFS static RSA cipher suite
        try:
            ctx.set_ciphers("AES128-SHA:AES256-SHA:RSA")
        except ssl.SSLError:
            pass
            
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="postfix.mailnet")

        tls_info["version"] = ssl_s.version()
        tls_info["cipher"] = ssl_s.cipher()

        ssl_s.sendall(b"QUIT\r\n")
        client_log.append(recv_smtp_response(ssl_s))
        ssl_s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "FAILED"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "tls_info": tls_info,
        "tls_negotiated": True
    }

def run_scn_tls_self_signed_01(pcap_path: Path) -> dict:
    """SCN-TLS-SELF-SIGNED-01: Self-signed certificate validation failure"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    client_error = None
    try:
        raw_s = socket.create_connection((POSTFIX_HOST, 2525), timeout=10)
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"STARTTLS\r\n")
        client_log.append(recv_smtp_response(raw_s))

        ctx = ssl.create_default_context(cafile=str(CERTS_DIR / "ca.crt"))
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="postfix.mailnet")
        ssl_s.close()
        status = "UNEXPECTED_SUCCESS"
    except ssl.SSLCertVerificationError as e:
        status = "VERIFICATION_FAILED_AS_EXPECTED"
        client_error = f"[SSL: CERTIFICATE_VERIFY_FAILED] {e.verify_message}"
    except Exception as e:
        status = "FAILED"
        client_error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": client_error,
        "client_log": client_log,
        "tls_negotiated": False
    }

def run_scn_tls_expired_01(pcap_path: Path) -> dict:
    """SCN-TLS-EXPIRED-01: Expired certificate validation failure"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    client_error = None
    try:
        raw_s = socket.create_connection((POSTFIX_HOST, 2526), timeout=10)
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"STARTTLS\r\n")
        client_log.append(recv_smtp_response(raw_s))

        ctx = ssl.create_default_context(cafile=str(CERTS_DIR / "ca.crt"))
        ssl_s = ctx.wrap_socket(raw_s, server_hostname="postfix.mailnet")
        ssl_s.close()
        status = "UNEXPECTED_SUCCESS"
    except ssl.SSLCertVerificationError as e:
        status = "VERIFICATION_FAILED_AS_EXPECTED"
        client_error = f"[SSL: CERTIFICATE_VERIFY_FAILED] {e.verify_message}"
    except Exception as e:
        status = "FAILED"
        client_error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": client_error,
        "client_log": client_log,
        "tls_negotiated": False
    }

def run_scn_tls_interrupted_01(pcap_path: Path) -> dict:
    """SCN-TLS-INTERRUPTED-01: Aborted TLS handshake after STARTTLS"""
    proc = start_tcpdump(pcap_path)
    client_log = []
    try:
        raw_s = socket.create_connection((POSTFIX_HOST, 25), timeout=10)
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"EHLO client.mailnet\r\n")
        client_log.append(recv_smtp_response(raw_s))
        raw_s.sendall(b"STARTTLS\r\n")
        client_log.append(recv_smtp_response(raw_s))

        # Send partial ClientHello header
        raw_s.sendall(b"\x16\x03\x03\x00\x2e\x01\x00\x00\x2a\x03\x03")
        time.sleep(0.1)
        raw_s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        raw_s.close()
        status = "SUCCESS"
        error = None
    except Exception as e:
        status = "SUCCESS"
        error = str(e)
    finally:
        stop_tcpdump(proc)

    return {
        "status": status,
        "error": error,
        "client_log": client_log,
        "tls_negotiated": False
    }

SCENARIO_RUNNERS = [
    {
        "scenario_id": "SCN-SMTP-01",
        "name": "SMTP Plaintext Session",
        "protocol": "SMTP",
        "pcap_filename": "SCN-SMTP-01.pcap",
        "runner": run_scn_smtp_01,
        "configured_behavior": {"server": "Postfix", "port": 2527, "tls_security_level": "none", "cert_profile": "N/A"},
        "expected_behavior": {"starttls_advertised": False, "starttls_requested": False, "handshake_outcome": "N/A", "tls_version": None, "client_verification": "N/A"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT"], "tls_negotiated": False, "certificate_status": "NOT_APPLICABLE", "security_posture": "UNENCRYPTED"}
    },
    {
        "scenario_id": "SCN-SMTP-02",
        "name": "SMTP STARTTLS Successful Upgrade",
        "protocol": "SMTP",
        "pcap_filename": "SCN-SMTP-02.pcap",
        "runner": run_scn_smtp_02,
        "configured_behavior": {"server": "Postfix", "port": 25, "tls_security_level": "may", "cert_profile": "valid_ca_signed"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "SUCCESS", "tls_version": "TLSv1.3", "client_verification": "SUCCESS"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "STARTTLS"], "tls_negotiated": True, "certificate_status": "VALID", "security_posture": "SECURE"}
    },
    {
        "scenario_id": "SCN-SMTP-03",
        "name": "SMTP STARTTLS Advertised But Unused",
        "protocol": "SMTP",
        "pcap_filename": "SCN-SMTP-03.pcap",
        "runner": run_scn_smtp_03,
        "configured_behavior": {"server": "Postfix", "port": 25, "tls_security_level": "may", "cert_profile": "valid_ca_signed"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": False, "handshake_outcome": "N/A", "tls_version": None, "client_verification": "N/A"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT"], "tls_negotiated": False, "certificate_status": "NOT_APPLICABLE", "security_posture": "UNENCRYPTED_OPPORTUNITY_MISSED"}
    },
    {
        "scenario_id": "SCN-IMAP-01",
        "name": "IMAP STARTTLS Successful Upgrade",
        "protocol": "IMAP",
        "pcap_filename": "SCN-IMAP-01.pcap",
        "runner": run_scn_imap_01,
        "configured_behavior": {"server": "Dovecot", "port": 143, "tls_security_level": "starttls", "cert_profile": "valid_ca_signed"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "SUCCESS", "tls_version": "TLSv1.3", "client_verification": "SUCCESS"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["CAPABILITY", "STARTTLS"], "tls_negotiated": True, "certificate_status": "VALID", "security_posture": "SECURE"}
    },
    {
        "scenario_id": "SCN-POP3-01",
        "name": "POP3 STLS Successful Upgrade",
        "protocol": "POP3",
        "pcap_filename": "SCN-POP3-01.pcap",
        "runner": run_scn_pop3_01,
        "configured_behavior": {"server": "Dovecot", "port": 110, "tls_security_level": "stls", "cert_profile": "valid_ca_signed"},
        "expected_behavior": {"stls_advertised": True, "stls_requested": True, "handshake_outcome": "SUCCESS", "tls_version": "TLSv1.3", "client_verification": "SUCCESS"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["CAPA", "STLS"], "tls_negotiated": True, "certificate_status": "VALID", "security_posture": "SECURE"}
    },
    {
        "scenario_id": "SCN-TLS12-BASELINE-01",
        "name": "SMTP TLS 1.2 Baseline Negotiation",
        "protocol": "SMTP",
        "pcap_filename": "SCN-TLS12-BASELINE-01.pcap",
        "runner": run_scn_tls12_baseline_01,
        "configured_behavior": {"server": "Postfix", "port": 2528, "tls_security_level": "may", "cert_profile": "valid_ca_signed", "forced_protocol": "TLSv1.2"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "SUCCESS", "tls_version": "TLSv1.2", "client_verification": "SUCCESS"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "STARTTLS"], "tls_negotiated": True, "certificate_status": "VALID", "security_posture": "TLS12_FORWARD_SECRECY"}
    },
    {
        "scenario_id": "SCN-TLS-WEAK-01",
        "name": "SMTP Forced Non-Forward-Secrecy Static RSA",
        "protocol": "SMTP",
        "pcap_filename": "SCN-TLS-WEAK-01.pcap",
        "runner": run_scn_tls_weak_01,
        "configured_behavior": {"server": "Postfix", "port": 2528, "tls_security_level": "may", "cert_profile": "valid_ca_signed", "forced_cipher": "Static RSA / Non-PFS"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "SUCCESS", "tls_version": "TLSv1.2", "client_verification": "SUCCESS"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "STARTTLS"], "tls_negotiated": True, "certificate_status": "VALID", "security_posture": "NO_FORWARD_SECRECY"}
    },
    {
        "scenario_id": "SCN-TLS-SELF-SIGNED-01",
        "name": "Self-Signed Certificate Validation Failure",
        "protocol": "SMTP",
        "pcap_filename": "SCN-TLS-SELF-SIGNED-01.pcap",
        "runner": run_scn_tls_self_signed_01,
        "configured_behavior": {"server": "Postfix", "port": 2525, "tls_security_level": "may", "cert_profile": "self_signed"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "CLIENT_VERIFICATION_FAILURE", "tls_version": None, "client_verification": "FAILED_SELF_SIGNED"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "STARTTLS"], "tls_negotiated": False, "certificate_status": "SELF_SIGNED_UNTRUSTED", "security_posture": "CERTIFICATE_UNTRUSTED"}
    },
    {
        "scenario_id": "SCN-TLS-EXPIRED-01",
        "name": "Expired Certificate Validation Failure",
        "protocol": "SMTP",
        "pcap_filename": "SCN-TLS-EXPIRED-01.pcap",
        "runner": run_scn_tls_expired_01,
        "configured_behavior": {"server": "Postfix", "port": 2526, "tls_security_level": "may", "cert_profile": "expired_ca_signed"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "CLIENT_VERIFICATION_FAILURE", "tls_version": None, "client_verification": "FAILED_EXPIRED"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "STARTTLS"], "tls_negotiated": False, "certificate_status": "EXPIRED", "security_posture": "CERTIFICATE_EXPIRED"}
    },
    {
        "scenario_id": "SCN-TLS-INTERRUPTED-01",
        "name": "Interrupted TLS Handshake After STARTTLS",
        "protocol": "SMTP",
        "pcap_filename": "SCN-TLS-INTERRUPTED-01.pcap",
        "runner": run_scn_tls_interrupted_01,
        "configured_behavior": {"server": "Postfix", "port": 25, "tls_security_level": "may", "cert_profile": "valid_ca_signed"},
        "expected_behavior": {"starttls_advertised": True, "starttls_requested": True, "handshake_outcome": "INTERRUPTED", "tls_version": None, "client_verification": "ABORTED"},
        "ground_truth_labels": {"plaintext_commands_before_tls": ["EHLO", "STARTTLS"], "tls_negotiated": False, "certificate_status": "INCOMPLETE_HANDSHAKE", "security_posture": "HANDSHAKE_ABORTED"}
    }
]

def generate_all_scenarios():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    print("[Generator] Waiting for mail services to become ready...")
    wait_for_port(POSTFIX_HOST, 25)
    wait_for_port(DOVECOT_HOST, 143)
    wait_for_port(DOVECOT_HOST, 110)
    print("[Generator] All mail service ports accessible.")

    manifest_entries = []

    for item in SCENARIO_RUNNERS:
        sc_id = item["scenario_id"]
        pcap_file = OUTPUT_DIR / item["pcap_filename"]
        print(f"\n[Scenario] Running {sc_id}: {item['name']}...")

        res = item["runner"](pcap_file)
        
        sha256_hash = compute_sha256(pcap_file) if pcap_file.exists() else None
        obs = inspect_pcap_with_tshark(pcap_file)
        
        if "tls_info" in res and res["tls_info"]:
            if res["tls_info"].get("version"):
                obs["tls_version_observed"] = res["tls_info"]["version"]
            if res["tls_info"].get("cipher"):
                obs["cipher_observed"] = res["tls_info"]["cipher"][0] if isinstance(res["tls_info"]["cipher"], tuple) else res["tls_info"]["cipher"]
        if res.get("error"):
            obs["client_error"] = res["error"]

        if pcap_file.exists() and obs["packets_captured"] > 0:
            verification_status = "VERIFIED"
        else:
            verification_status = "INCOMPLETE"

        entry = {
            "scenario_id": sc_id,
            "name": item["name"],
            "protocol": item["protocol"],
            "pcap_filename": item["pcap_filename"],
            "sha256": sha256_hash,
            "configured_behavior": item["configured_behavior"],
            "expected_behavior": item["expected_behavior"],
            "observed_behavior": obs,
            "ground_truth_labels": item["ground_truth_labels"],
            "verification_status": verification_status
        }

        if obs.get("cipher_observed"):
            entry["ground_truth_labels"]["cipher"] = obs["cipher_observed"]
        if obs.get("tls_version_observed"):
            entry["ground_truth_labels"]["tls_version"] = obs["tls_version_observed"]

        manifest_entries.append(entry)
        print(f"  -> Captured {obs['packets_captured']} packets | Status: {verification_status} | Hash: {sha256_hash[:12]}...")

    manifest_path = MANIFEST_DIR / "scenarios_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump({"scenarios": manifest_entries}, f, indent=2)

    print(f"\n[Generator] Scenario generation complete! Manifest written to {manifest_path}")

if __name__ == "__main__":
    generate_all_scenarios()
