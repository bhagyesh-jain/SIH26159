import os
import pytest
import tempfile
from pathlib import Path
from scapy.all import wrpcap, Ether, IP, TCP, Raw
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.database import Base, engine, SessionLocal


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Sets up an isolated clean SQLite database for testing."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """Provides a FastAPI test client instance."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    """Provides a fresh database session per test."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def synthetic_pcap_file(tmp_path: Path) -> Path:
    """
    Generates a real, valid synthetic PCAP capture file with 1 TCP stream containing SMTP traffic:
    Client (192.168.1.100:54321) <--> Server (192.168.1.250:25)
    """
    pcap_path = tmp_path / "synthetic_smtp.pcap"

    # Packet 1: SYN
    pkt1 = Ether() / IP(src="192.168.1.100", dst="192.168.1.250") / TCP(sport=54321, dport=25, flags="S", seq=1000)
    # Packet 2: SYN-ACK
    pkt2 = Ether() / IP(src="192.168.1.250", dst="192.168.1.100") / TCP(sport=25, dport=54321, flags="SA", seq=2000, ack=1001)
    # Packet 3: ACK
    pkt3 = Ether() / IP(src="192.168.1.100", dst="192.168.1.250") / TCP(sport=54321, dport=25, flags="A", seq=1001, ack=2001)
    # Packet 4: SMTP Banner from Server
    pkt4 = Ether() / IP(src="192.168.1.250", dst="192.168.1.100") / TCP(sport=25, dport=54321, flags="PA", seq=2001, ack=1001) / Raw(load=b"220 mail.securemailscope.local ESMTP Postfix\r\n")
    # Packet 5: EHLO from Client
    pkt5 = Ether() / IP(src="192.168.1.100", dst="192.168.1.250") / TCP(sport=54321, dport=25, flags="PA", seq=1001, ack=2047) / Raw(load=b"EHLO client.securemailscope.local\r\n")

    packets = [pkt1, pkt2, pkt3, pkt4, pkt5]
    wrpcap(str(pcap_path), packets)

    return pcap_path


@pytest.fixture
def synthetic_pcapng_file(tmp_path: Path) -> Path:
    """
    Generates a valid minimal synthetic PCAPNG binary file fixture.
    Format starts with Section Header Block magic: 0x0a0d0d0a
    """
    pcapng_path = tmp_path / "synthetic.pcapng"
    
    # Minimal PCAPNG Section Header Block (SHB) binary structure
    shb_header = (
        b"\x0a\x0d\x0d\x0a"  # Block Type (SHB)
        b"\x1c\x00\x00\x00"  # Block Total Length (28 bytes)
        b"\x4d\x3c\xb2\xa1"  # Byte-Order Magic
        b"\x01\x00\x00\x00"  # Major Version (1)
        b"\x00\x00\x00\x00"  # Minor Version (0)
        b"\xff\xff\xff\xff\xff\xff\xff\xff"  # Section Length (-1)
        b"\x1c\x00\x00\x00"  # Block Total Length repeated
    )
    with open(pcapng_path, "wb") as f:
        f.write(shb_header)

    return pcapng_path
