import pytest
from fastapi import HTTPException
from backend.app.services.capture_service import validate_capture_magic_bytes


def test_validate_pcap_magic_bytes():
    """Verify PCAP magic bytes format detection."""
    pcap_header_be = b"\xa1\xb2\xc3\xd4\x00\x02"
    pcap_header_le = b"\xd4\xc3\xb2\xa1\x00\x02"

    assert validate_capture_magic_bytes(pcap_header_be) == "PCAP"
    assert validate_capture_magic_bytes(pcap_header_le) == "PCAP"


def test_validate_pcapng_magic_bytes():
    """Verify PCAPNG magic bytes format detection."""
    pcapng_header = b"\x0a\x0d\x0d\x0a\x1c\x00"
    assert validate_capture_magic_bytes(pcapng_header) == "PCAPNG"


def test_reject_invalid_magic_bytes():
    """Verify rejection of non-PCAP files (e.g. plain text or executable)."""
    text_header = b"HELLO WORLD"
    exe_header = b"MZ\x90\x00\x03\x00"

    with pytest.raises(HTTPException) as exc_info:
        validate_capture_magic_bytes(text_header)
    assert exc_info.value.status_code == 400
    assert "Invalid capture file header" in exc_info.value.detail

    with pytest.raises(HTTPException) as exc_info2:
        validate_capture_magic_bytes(exe_header)
    assert exc_info2.value.status_code == 400
