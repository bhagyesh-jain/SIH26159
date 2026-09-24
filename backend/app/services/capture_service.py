import hashlib
import uuid
from pathlib import Path
from typing import Tuple
from fastapi import UploadFile, HTTPException
from backend.app.core.config import UPLOADS_DIR, MAX_UPLOAD_SIZE_BYTES

# PCAP Magic Bytes
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_NANO_BE = b"\xa1\xb2\x3c\x4d"
PCAP_NANO_LE = b"\x4d\x3c\xb2\xa1"

# PCAPNG Magic Bytes (Section Header Block)
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def validate_capture_magic_bytes(header: bytes) -> str:
    """
    Validates capture magic bytes.
    Returns format string: 'PCAP' or 'PCAPNG'
    Raises HTTPException if invalid.
    """
    if len(header) < 4:
        raise HTTPException(status_code=400, detail="File too small to be a valid PCAP/PCAPNG capture.")

    first_4 = header[:4]

    if first_4 in (PCAP_MAGIC_BE, PCAP_MAGIC_LE, PCAP_NANO_BE, PCAP_NANO_LE):
        return "PCAP"
    elif first_4 == PCAPNG_MAGIC:
        return "PCAPNG"
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid capture file header: magic bytes {first_4.hex()} do not match PCAP or PCAPNG specifications."
        )


def process_and_save_upload(upload_file: UploadFile) -> Tuple[str, str, int, str, Path]:
    """
    Reads upload stream, validates magic bytes, computes SHA-256 hash,
    enforces maximum size, and saves file to immutable storage.
    Returns (capture_id, sha256_hash, byte_size, format_str, target_path)
    """
    header_bytes = upload_file.file.read(4)
    format_str = validate_capture_magic_bytes(header_bytes)

    # Reset file position to start for complete hash & storage
    upload_file.file.seek(0)

    sha256_hash = hashlib.sha256()
    total_bytes = 0
    capture_id = f"cap_{uuid.uuid4().hex[:12]}"
    filename = upload_file.filename or "capture.pcap"
    extension = Path(filename).suffix or ".pcap"
    
    target_filename = f"{capture_id}_{sha256_hash.hexdigest()[:8]}{extension}"
    target_path = UPLOADS_DIR / target_filename

    # Read in chunks to handle memory safely
    with open(target_path, "wb") as f_out:
        while True:
            chunk = upload_file.file.read(64 * 1024)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                # Clean up partial file
                f_out.close()
                if target_path.exists():
                    target_path.unlink()
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed upload size of {MAX_UPLOAD_SIZE_BYTES / (1024*1024):.0f} MB."
                )
            sha256_hash.update(chunk)
            f_out.write(chunk)

    final_hash = sha256_hash.hexdigest()
    return capture_id, final_hash, total_bytes, format_str, target_path
