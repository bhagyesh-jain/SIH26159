import datetime
from sqlalchemy import (
    Column, String, Integer, DateTime, ForeignKey, Text, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from backend.app.core.config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="ACTIVE")

    captures = relationship("Capture", back_populates="investigation", cascade="all, delete-orphan")


class Capture(Base):
    __tablename__ = "captures"

    id = Column(String, primary_key=True, index=True)
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False)
    filename = Column(String, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    bytes = Column(Integer, nullable=False)
    format = Column(String, nullable=False)  # PCAP or PCAPNG
    stored_path = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    tshark_version = Column(String, nullable=True)

    investigation = relationship("Investigation", back_populates="captures")
    jobs = relationship("AnalysisJob", back_populates="capture", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="capture", cascade="all, delete-orphan")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String, primary_key=True, index=True)
    capture_id = Column(String, ForeignKey("captures.id"), nullable=False)
    state = Column(String, nullable=False, default="QUEUED")  # QUEUED, PROCESSING, COMPLETED, FAILED
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    error_code = Column(String, nullable=True)
    parser_version = Column(String, nullable=True)

    capture = relationship("Capture", back_populates="jobs")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, index=True)
    capture_id = Column(String, ForeignKey("captures.id"), nullable=False)
    tcp_stream = Column(Integer, nullable=False, index=True)
    src = Column(String, nullable=False)
    dst = Column(String, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String, default="UNKNOWN")  # SMTP, IMAP, POP3, UNKNOWN
    completeness = Column(String, default="COMPLETE")  # COMPLETE, INCOMPLETE
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)

    capture = relationship("Capture", back_populates="sessions")
    events = relationship("Event", back_populates="session", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="session", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    packet_number = Column(Integer, nullable=False)
    event_type = Column(String, nullable=False)  # PACKET, COMMAND, RESPONSE, TLS_HANDSHAKE
    timestamp = Column(String, nullable=True)
    observed_json = Column(Text, nullable=False)  # JSON text

    session = relationship("Session", back_populates="events")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False, index=True)
    event_type = Column(String, nullable=False)  # e.g., GREETING, CAPABILITY_ADVERTISED, UPGRADE_REQUESTED, TLS_HANDSHAKE
    protocol = Column(String, nullable=False)    # SMTP, IMAP, POP3, UNKNOWN
    upgrade_status = Column(String, nullable=True) # NOT_OFFERED, OFFERED_NOT_USED, REQUESTED, ACCEPTED, NEGOTIATED, REJECTED, FAILED, UNKNOWN
    observed_value = Column(Text, nullable=False)
    frame_numbers = Column(String, nullable=True) # e.g. "4,6,8"
    timestamp = Column(String, nullable=True)
    evidence_source = Column(String, nullable=False, default="TSHARK_REASSEMBLED_STREAM")
    completeness_status = Column(String, nullable=False, default="COMPLETE") # COMPLETE, TRUNCATED, INCOMPLETE
    details_json = Column(Text, nullable=True)   # JSON string with evidence fields

    session = relationship("Session", back_populates="security_events")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, index=True)
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False, index=True)
    rule_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String, nullable=False)  # HIGH, MEDIUM, LOW, UNKNOWN
    risk_score = Column(Integer, nullable=False)  # Deterministic score (0-100)
    status = Column(String, nullable=False, default="ACTIVE")  # ACTIVE, SUPPRESSED
    protocol = Column(String, nullable=False)  # SMTP, IMAP, POP3, UNKNOWN
    observed_value = Column(Text, nullable=False)
    evidence_event_ids = Column(Text, nullable=False)  # JSON array string, e.g. '["sevt_1", "sevt_2"]'
    evidence_frame_numbers = Column(Text, nullable=False)  # JSON array string, e.g. '[4, 6, 8, 10]'
    first_seen = Column(String, nullable=True)
    last_seen = Column(String, nullable=True)
    details_json = Column(Text, nullable=True)  # JSON string with structured details

    session = relationship("Session", back_populates="findings")
    investigation = relationship("Investigation")


def init_db():
    Base.metadata.create_all(bind=engine)


def ensure_schema_migrated(db_engine=engine):
    """
    Safely ensures all tables (including security_events) exist without modifying
    or overwriting existing tables or records.
    """
    Base.metadata.create_all(bind=db_engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
