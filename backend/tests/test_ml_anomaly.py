import os
import json
import hashlib
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.database import (
    get_db,
    Investigation,
    Capture,
    Session,
    SecurityEvent,
    Finding,
    init_db,
    ensure_schema_migrated,
)
from backend.app.services.stream_service import process_capture_streams
from backend.app.services.finding_service import FindingService
from backend.app.services.ml_feature_service import extract_session_features, FEATURE_NAMES
from backend.app.services.ml_anomaly_service import (
    PurePythonIsolationForest,
    compute_investigation_anomalies,
    MODEL_VERSION,
    FEATURE_VERSION,
)

client = TestClient(app)
SYNTHETIC_PCAP_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "pcaps" / "synthetic"


@pytest.fixture(autouse=True)
def setup_test_db():
    ensure_schema_migrated()
    yield


def test_no_pcap_filename_or_scenario_leakage_in_features():
    """Requirement 14 & 24: Verify scenario names and PCAP filenames NEVER enter the feature vector."""
    for feat_name in FEATURE_NAMES:
        assert "pcap" not in feat_name.lower()
        assert "filename" not in feat_name.lower()
        assert "scenario" not in feat_name.lower()
        assert "manifest" not in feat_name.lower()


def test_pure_python_isolation_forest_reproducibility():
    """Requirement 9 & 13: Verify Isolation Forest produces 100% deterministic predictions."""
    X = [
        [10.0, 1.0, 0.0, 0.0, 0.0, 5.0, 1.0, 75.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        [5.0, 1.0, 0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0],
        [12.0, 0.0, 1.0, 0.0, 0.0, 6.0, 1.0, 60.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0],
        [2.0, 0.0, 0.0, 1.0, 0.0, 2.0, 1.0, 75.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    ]

    model1 = PurePythonIsolationForest(n_estimators=50, max_samples=256, random_state=42)
    model1.fit(X)
    scores1 = [model1.compute_anomaly_score(row) for row in X]

    model2 = PurePythonIsolationForest(n_estimators=50, max_samples=256, random_state=42)
    model2.fit(X)
    scores2 = [model2.compute_anomaly_score(row) for row in X]

    assert scores1 == scores2


def test_port_and_protocol_bias_control():
    """Requirement 5: Ephemeral source ports are excluded and one-hot protocol is used to prevent artificial port noise."""
    db = next(get_db())
    inv = Investigation(id="inv_port_bias", title="Port Bias Inv")
    db.add(inv)
    db.commit()

    cap = Capture(
        id="cap_port_bias",
        investigation_id="inv_port_bias",
        filename="test.pcap",
        sha256="e" * 64,
        bytes=1000,
        format="PCAP",
        stored_path="/tmp/test.pcap",
    )
    db.add(cap)
    db.commit()

    # Create two identical sessions with different ephemeral source ports
    sess1 = Session(id="s1", capture_id="cap_port_bias", tcp_stream=1, src="10.0.0.1", dst="10.0.0.2", src_port=12345, dst_port=25, protocol="SMTP")
    sess2 = Session(id="s2", capture_id="cap_port_bias", tcp_stream=2, src="10.0.0.1", dst="10.0.0.2", src_port=58912, dst_port=25, protocol="SMTP")
    db.add_all([sess1, sess2])
    db.commit()

    v1 = extract_session_features(sess1, [], [], "inv_port_bias")
    v2 = extract_session_features(sess2, [], [], "inv_port_bias")

    # The numeric feature vectors must be identical because ephemeral source ports are excluded
    assert v1.to_numeric_array() == v2.to_numeric_array()


def test_small_baseline_n_lessthan_or_equal_2_behavior():
    """Requirement 6: Small baseline (n <= 2) explicitly informs analyst of limited baseline volume."""
    db = next(get_db())
    inv = Investigation(id="inv_small_base", title="Small Base Inv")
    db.add(inv)
    db.commit()

    cap = Capture(id="cap_sb", investigation_id="inv_small_base", filename="sb.pcap", sha256="f" * 64, bytes=500, format="PCAP", stored_path="/tmp/sb.pcap")
    db.add(cap)
    db.commit()

    sess = Session(id="s_sb_1", capture_id="cap_sb", tcp_stream=1, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP")
    db.add(sess)
    db.commit()

    resp = client.get("/api/v1/investigations/inv_small_base/anomalies")
    assert resp.status_code == 200
    data = resp.json()

    assert "n <= 2 sessions" in data["training_context"].lower()
    assert "not attack probabilities" in data["training_context"].lower()
    assert data["results"][0]["confidence_band"] == "LOW"


def test_deterministic_finding_independence():
    """Requirement 11: ML anomaly detection cannot alter Findings, severity, status, or risk scores."""
    db = next(get_db())
    inv = Investigation(id="inv_indep", title="Indep Inv")
    db.add(inv)
    db.commit()

    cap = Capture(id="cap_indep", investigation_id="inv_indep", filename="indep.pcap", sha256="1" * 64, bytes=1000, format="PCAP", stored_path="/tmp/indep.pcap")
    db.add(cap)
    db.commit()

    sess = Session(id="s_indep", capture_id="cap_indep", tcp_stream=1, src="10.0.0.1", dst="10.0.0.2", src_port=1000, dst_port=25, protocol="SMTP")
    db.add(sess)
    db.commit()

    fnd = Finding(
        id="fnd_indep_001",
        investigation_id="inv_indep",
        session_id="s_indep",
        rule_id="EMAIL-PLAINTEXT-NOT-OFFERED-001",
        title="Plaintext Email",
        description="Plaintext email detected",
        severity="HIGH",
        confidence="HIGH",
        risk_score=75,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="PLAINTEXT",
        evidence_event_ids=json.dumps([]),
        evidence_frame_numbers=json.dumps([1, 2]),
    )
    db.add(fnd)
    db.commit()

    # Compute anomalies
    client.get("/api/v1/investigations/inv_indep/anomalies")

    # Verify Finding remains bit-identical
    fnd_after = db.query(Finding).filter(Finding.id == "fnd_indep_001").first()
    assert fnd_after.severity == "HIGH"
    assert fnd_after.confidence == "HIGH"
    assert fnd_after.risk_score == 75
    assert fnd_after.status == "ACTIVE"


def test_all_ten_synthetic_scenarios_ground_truth_and_ml_evaluation():
    """
    Ground-Truth Audit Test: Verifies all 10 synthetic lab scenarios end-to-end.
    Confirms ground truth posture, deterministic findings, and ML anomaly responses.
    """
    scenarios = [
        ("SCN-SMTP-01.pcap", "SMTP", "EMAIL-PLAINTEXT-NOT-OFFERED-001"),
        ("SCN-SMTP-02.pcap", "SMTP", "TLS-SECURE-BASELINE-001"),
        ("SCN-SMTP-03.pcap", "SMTP", "EMAIL-STARTTLS-OFFERED-NOT-USED-001"),
        ("SCN-IMAP-01.pcap", "IMAP", "TLS-SECURE-BASELINE-001"),
        ("SCN-POP3-01.pcap", "POP3", "TLS-SECURE-BASELINE-001"),
        ("SCN-TLS12-BASELINE-01.pcap", "SMTP", "TLS-SECURE-BASELINE-001"),
        ("SCN-TLS-WEAK-01.pcap", "SMTP", "TLS-WEAK-STATIC-RSA-001"),
        ("SCN-TLS-SELF-SIGNED-01.pcap", "SMTP", "TLS-ALERT-CERT-OBSERVED-001"),
        ("SCN-TLS-EXPIRED-01.pcap", "SMTP", "TLS-ALERT-CERT-OBSERVED-001"),
        ("SCN-TLS-INTERRUPTED-01.pcap", "SMTP", "TLS-HANDSHAKE-FAILED-001"),
    ]

    db = next(get_db())

    for pcap_name, expected_proto, expected_rule in scenarios:
        pcap_path = SYNTHETIC_PCAP_DIR / pcap_name
        assert pcap_path.exists(), f"Synthetic PCAP not found: {pcap_name}"

        inv_res = client.post("/api/v1/investigations", json={"title": f"Ground Truth Audit {pcap_name}"})
        assert inv_res.status_code == 201
        inv_id = inv_res.json()["id"]

        with open(pcap_path, "rb") as f:
            up_res = client.post(
                f"/api/v1/investigations/{inv_id}/captures",
                files={"file": (pcap_name, f, "application/octet-stream")},
            )
        assert up_res.status_code == 202

        # Query findings to confirm deterministic ground truth
        findings = db.query(Finding).filter(Finding.investigation_id == inv_id, Finding.status == "ACTIVE").all()
        rule_ids = [f.rule_id for f in findings]
        assert expected_rule in rule_ids, f"Expected deterministic rule {expected_rule} for {pcap_name}, got {rule_ids}"

        # Query ML anomaly response
        anom_res = client.get(f"/api/v1/investigations/{inv_id}/anomalies")
        assert anom_res.status_code == 200
        anom_data = anom_res.json()

        assert anom_data["summary"]["total_sessions_analyzed"] >= 1
        assert len(anom_data["results"]) >= 1


def test_get_anomalies_missing_investigation_404():
    """Requirement 18: Missing investigation returns 404."""
    resp = client.get("/api/v1/investigations/inv_non_existent_id/anomalies")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_anomalies_empty_investigation():
    """Requirement 18: Investigation with no captures/sessions returns valid empty dataset."""
    db = next(get_db())
    inv = Investigation(id="inv_ml_empty_001", title="Empty Inv")
    db.add(inv)
    db.commit()

    resp = client.get("/api/v1/investigations/inv_ml_empty_001/anomalies")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == "inv_ml_empty_001"
    assert data["model_version"] == MODEL_VERSION
    assert data["feature_version"] == FEATURE_VERSION
    assert data["summary"]["total_sessions_analyzed"] == 0
    assert data["results"] == []


def test_investigation_isolation():
    """Requirement 18 & 22: Verify anomalies in Investigation A do not leak into Investigation B."""
    db = next(get_db())

    invA = Investigation(id="inv_ml_iso_A", title="Investigation A")
    invB = Investigation(id="inv_ml_iso_B", title="Investigation B")
    db.add_all([invA, invB])
    db.commit()

    capA = Capture(
        id="cap_iso_A",
        investigation_id="inv_ml_iso_A",
        filename="testA.pcap",
        sha256="a" * 64,
        bytes=1000,
        format="PCAP",
        stored_path="/tmp/testA.pcap",
    )
    capB = Capture(
        id="cap_iso_B",
        investigation_id="inv_ml_iso_B",
        filename="testB.pcap",
        sha256="b" * 64,
        bytes=2000,
        format="PCAP",
        stored_path="/tmp/testB.pcap",
    )
    db.add_all([capA, capB])
    db.commit()

    sessA = Session(
        id="sess_iso_A",
        capture_id="cap_iso_A",
        tcp_stream=1,
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=1234,
        dst_port=25,
        protocol="SMTP",
    )
    sessB = Session(
        id="sess_iso_B",
        capture_id="cap_iso_B",
        tcp_stream=1,
        src="192.168.1.1",
        dst="192.168.1.2",
        src_port=5678,
        dst_port=143,
        protocol="IMAP",
    )
    db.add_all([sessA, sessB])
    db.commit()

    respA = client.get("/api/v1/investigations/inv_ml_iso_A/anomalies")
    assert respA.status_code == 200
    dataA = respA.json()
    assert dataA["summary"]["total_sessions_analyzed"] == 1
    assert dataA["results"][0]["session_id"] == "sess_iso_A"

    respB = client.get("/api/v1/investigations/inv_ml_iso_B/anomalies")
    assert respB.status_code == 200
    dataB = respB.json()
    assert dataB["summary"]["total_sessions_analyzed"] == 1
    assert dataB["results"][0]["session_id"] == "sess_iso_B"


def test_ml_anomaly_end_to_end_starttls_bypass():
    """Verify anomaly detection for STARTTLS advertised but unused scenario."""
    db = next(get_db())

    inv = Investigation(id="inv_ml_starttls_001", title="STARTTLS Bypass Inv")
    db.add(inv)
    db.commit()

    cap = Capture(
        id="cap_ml_starttls_001",
        investigation_id="inv_ml_starttls_001",
        filename="smtp_bypass.pcap",
        sha256="c" * 64,
        bytes=1500,
        format="PCAP",
        stored_path="/tmp/bypass.pcap",
    )
    db.add(cap)
    db.commit()

    sess = Session(
        id="sess_ml_bypass_001",
        capture_id="cap_ml_starttls_001",
        tcp_stream=0,
        src="192.168.1.10",
        dst="192.168.1.25",
        src_port=51200,
        dst_port=25,
        protocol="SMTP",
        completeness="COMPLETE",
    )
    db.add(sess)
    db.commit()

    sevt = SecurityEvent(
        id="sevt_ml_bypass_001",
        session_id="sess_ml_bypass_001",
        event_type="UPGRADE_REQUESTED",
        protocol="SMTP",
        upgrade_status="OFFERED_NOT_USED",
        observed_value="STARTTLS advertised but cleartext MAIL FROM transmitted",
        frame_numbers="4,6,8",
        completeness_status="COMPLETE",
    )
    fnd = Finding(
        id="fnd_ml_bypass_001",
        investigation_id="inv_ml_starttls_001",
        session_id="sess_ml_bypass_001",
        rule_id="EMAIL-STARTTLS-OFFERED-NOT-USED-001",
        title="STARTTLS Offered But Not Used",
        description="STARTTLS advertised by server but cleartext mail sent",
        severity="CRITICAL",
        confidence="HIGH",
        risk_score=90,
        status="ACTIVE",
        protocol="SMTP",
        observed_value="OFFERED_NOT_USED",
        evidence_event_ids=json.dumps(["sevt_ml_bypass_001"]),
        evidence_frame_numbers=json.dumps([4, 6, 8]),
    )
    db.add_all([sevt, fnd])
    db.commit()

    resp = client.get("/api/v1/investigations/inv_ml_starttls_001/anomalies")
    assert resp.status_code == 200
    data = resp.json()

    assert data["summary"]["total_sessions_analyzed"] == 1
    result = data["results"][0]

    assert result["session_id"] == "sess_ml_bypass_001"
    assert result["tcp_stream"] == 0
    assert result["protocol"] == "SMTP"
    assert result["supporting_finding_ids"] == ["fnd_ml_bypass_001"]
    assert result["supporting_event_ids"] == ["sevt_ml_bypass_001"]
    assert result["supporting_frame_numbers"] == [4, 6, 8]
    assert "STARTTLS" in result["explanation"]


def test_security_contract_no_secrets_or_private_paths():
    """Requirement 20: Verify API response never leaks paths or credentials."""
    db = next(get_db())

    inv = Investigation(id="inv_ml_sec_contract", title="Security Contract")
    db.add(inv)
    db.commit()

    cap = Capture(
        id="cap_sec_contract",
        investigation_id="inv_ml_sec_contract",
        filename="secret.pcap",
        sha256="d" * 64,
        bytes=1000,
        format="PCAP",
        stored_path="C:\\Secret\\Private\\InternalPath\\secret.pcap",
    )
    db.add(cap)
    db.commit()

    sess = Session(
        id="sess_sec_contract",
        capture_id="cap_sec_contract",
        tcp_stream=1,
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=1000,
        dst_port=25,
        protocol="SMTP",
    )
    db.add(sess)
    db.commit()

    resp = client.get("/api/v1/investigations/inv_ml_sec_contract/anomalies")
    assert resp.status_code == 200
    raw_str = resp.text

    assert "C:\\Secret\\Private" not in raw_str
    assert "stored_path" not in raw_str
    assert "password" not in raw_str.lower()
    assert "private_key" not in raw_str.lower()
