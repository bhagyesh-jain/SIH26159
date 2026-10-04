# SecureMailScope — Technical Architecture

**Version:** 1.0 proposed | **Principle:** modular monolith, local-first, evidence-first.

## 1. Stack
| Layer | Choice | Rationale |
|---|---|---|
| Web | React + TypeScript + Vite | Typed fast SPA |
| UI | Tailwind CSS, shadcn/ui, Lucide | Accessible dashboard primitives |
| Animation | Motion; selective React Bits | Controlled, reduced-motion-aware interactions |
| Charts | Recharts; optional Bklit after license/API verification | Avoid duplicate chart stacks initially |
| API | Python, FastAPI, Pydantic | Typed ingestion and analysis APIs |
| Packet parsing | TShark CLI, pinned version | Mature protocol dissection and TCP reassembly |
| Crypto | Python `cryptography` | X.509 and cryptographic property inspection |
| Storage | SQLite in development; PostgreSQL migration path | Simple first deployment |
| Jobs | In-process bounded worker for prototype; RQ/Redis later | Nonblocking capture analysis |
| ML | pandas, NumPy, scikit-learn Isolation Forest | Explainable baseline anomaly workflow |
| Reports | Jinja2 HTML, ReportLab PDF, JSON | Consistent exports |
| Lab | Docker Compose, Postfix, Dovecot, OpenSSL, tcpdump | Repeatable authorized captures |
| Tests | pytest, Vitest, Playwright | Unit, integration, E2E |

## 2. Logical data flow
```mermaid
flowchart TD
    A[React investigation UI] --> B[FastAPI REST API]
    B --> C[Validate capture and compute SHA-256]
    C --> D[(Original PCAP storage)]
    C --> E[Bounded analysis job]
    E --> F[TShark extraction and TCP reassembly]
    F --> G[Normalize streams and protocol events]
    G --> H[STARTTLS/STLS and TLS state machine]
    H --> I[Certificate and cryptographic feature extraction]
    I --> J[Deterministic rule engine]
    I --> K[Optional anomaly detector]
    J --> L[Evidence-backed assessment]
    K --> L
    L --> M[(Relational metadata store)]
    M --> N[Session and finding APIs]
    N --> A
    M --> O[JSON / HTML / PDF reports]
```

## 3. Modules and contracts
- `capture_service`: MIME-independent magic-byte validation for PCAP/PCAPNG, size caps, content hash, immutable originals, temporary staging and cleanup.
- `tshark_adapter`: explicit executable discovery/version check, argument-array subprocess, timeouts, output-size limits, error capture; avoid invoking through shell.
- `stream_service`: map `tcp.stream` to ordered packet references; detect gaps, retransmissions, out-of-order packets and truncated capture; never claim a full original session if capture incomplete.
- `protocol_detector`: protocol dissector output plus command signatures and standard ports as supporting hints; explicit unknown state.
- `upgrade_parser`: per-protocol SMTP STARTTLS, IMAP STARTTLS, POP3 STLS state machines with server response, TLS start, success/failure and incomplete states.
- `tls_parser`: ClientHello/ServerHello, selected cipher, protocol version, alerts, visible certificates and handshake completeness; distinguish offered versus negotiated versions and ciphers.
- `certificate_service`: parse only available certificate bytes; expiry relative to captured timestamp and current assessment date as separate checks; trust chain validation only with documented trust anchors and intermediates; TLS 1.3 passive visibility limits.
- `rule_engine`: versioned deterministic rules with rule ID, severity, observation, applicability, confidence, evidence and remediation.
- `ml_service`: offline training/evaluation, model artifact versioning and advisory anomaly outputs; never overwrite deterministic findings.
- `report_service`: one canonical assessment schema rendered to JSON, HTML and PDF.

## 4. Data model
- `investigations(id, title, created_at, status)`
- `captures(id, investigation_id, filename, sha256, bytes, format, stored_path, uploaded_at, tshark_version)`
- `analysis_jobs(id, capture_id, state, started_at, ended_at, error_code, parser_version)`
- `sessions(id, capture_id, tcp_stream, src, dst, src_port, dst_port, protocol, completeness, started_at, ended_at)`
- `events(id, session_id, packet_number, event_type, timestamp, observed_json)`
- `tls_handshakes(id, session_id, version, cipher, outcome, completeness, evidence_json)`
- `certificates(id, handshake_id, fingerprint, subject, issuer, not_before, not_after, public_key, signature_algorithm, validation_json)`
- `security_events(id, session_id, event_type, protocol, upgrade_status, observed_value, frame_numbers, timestamp, evidence_source, completeness_status, details_json)`
- `findings(id, investigation_id, session_id, rule_id, title, description, severity, confidence, risk_score, status, protocol, observed_value, evidence_event_ids, evidence_frame_numbers, first_seen, last_seen, details_json)`
- `ml_assessments(id, session_id, model_version, anomaly_score, feature_json, explanation_json)`
- `reports(id, investigation_id, format, created_at, path, assessment_version)`

Use SQLAlchemy and Alembic from the beginning. Never persist uploaded secrets or plaintext passwords in logs, security event metadata, or finding details. `evidence_event_ids` and `evidence_frame_numbers` are stored as structured JSON string arrays in the database.

## 5. API v1
- `GET /api/v1/health` — runtime health and TShark availability (no sensitive paths publicly exposed).
- `POST /api/v1/investigations` — create case.
- `GET /api/v1/investigations` — list cases.
- `POST /api/v1/investigations/{id}/captures` — upload and queue analysis.
- `GET /api/v1/jobs/{id}` — queued/running/completed/failed and stage; no fabricated percent.
- `GET /api/v1/investigations/{id}/sessions` — paginated, filterable session list.
- `GET /api/v1/sessions/{id}` — event timeline and evidence.
- `GET /api/v1/sessions/{session_id}/security-events` — filterable security events for a specific session (`protocol`, `event_type`, `upgrade_status`, `limit`, `offset`).
- `GET /api/v1/investigations/{investigation_id}/security-events` — filterable security events across all sessions in an investigation (`protocol`, `event_type`, `upgrade_status`, `limit`, `offset`).
- `GET /api/v1/sessions/{session_id}/findings` — filterable deterministic findings for a specific session (`severity`, `confidence`, `protocol`, `rule_id`, `limit`, `offset`).
- `GET /api/v1/investigations/{investigation_id}/findings` — filterable deterministic findings across all sessions in an investigation (`severity`, `confidence`, `protocol`, `rule_id`, `limit`, `offset`).
- `GET /api/v1/investigations/{id}/summary` — aggregate counts, score and coverage.
- `POST /api/v1/investigations/{id}/reports` — export requested format.

Response envelopes: IDs, status, timestamps, data, warnings, analysis limitations and structured errors. Use OpenAPI-generated TypeScript clients or shared typed schemas.

## 6. Capture security and threat model
Untrusted uploads can exploit parsers or exhaust resources. Enforce extension + magic bytes + maximum size; process with dedicated low-privilege worker, isolated temp directory, timeout, resource quotas and pinned TShark security updates. Limit path traversal, command injection, decompression bombs (if archives ever allowed), SSRF and arbitrary file reads. Never execute uploaded content. Default loopback-only server; authenticated access before multiuser deployment. Retention/deletion policies must cover raw captures, exports, key logs and backups.

## 7. Cryptographic limitations and evidence confidence semantics
Passive TLS 1.3 captures encrypt handshake messages following ServerHello (EncryptedExtensions, Certificate, Finished); optional authorized TLS key logs must be explicitly provided and protected to inspect certificate fields. Capture may omit intermediates, OCSP, DNS context or original client trust store.

Key exchange classification rules:
- TLS 1.3 key exchange is NOT inferred solely from cipher suites (e.g. `TLS_AES_256_GCM_SHA384`). The engine inspects observable key-share parameters in ClientHello/ServerHello (e.g. `X25519`). If key-share evidence is unobserved, `key_exchange` is marked `UNKNOWN`.
- TLS 1.2 `TLS_RSA_WITH_*` static RSA ciphers are classified as `STATIC_RSA` (`NO_PFS_STATIC_RSA`), whereas `TLS_ECDHE_*` ciphers are classified as `ECDHE` (`PFS ENABLED`).

Evidence confidence levels for handshake completion:
- `OBSERVED_COMPLETION`: ClientHello, ServerHello, and unencrypted Finished message (handshake type 20) explicitly observed in stream.
- `STRONGLY_SUPPORTED_COMPLETION`: ClientHello, ServerHello, and post-ServerHello encrypted record exchange observed with zero fatal alerts or resets.
- `FAILED`: Fatal TLS alert (level 2) or premature TCP Reset (`[RST]`) interrupts handshake negotiation; fatal alerts/resets unconditionally override generic negotiation classification.
- `UNKNOWN_OUTCOME`: Stream truncated immediately after ServerHello before post-handshake record exchange can be confirmed.

## 8. Synthetic lab design
`synthetic-lab/docker-compose.yml` starts isolated email servers and traffic generator; `scenarios/*.yaml` declares protocol, server TLS policy, certificate profile, expected server behavior, capture filter, number of sessions and seed. Capture on the isolated bridge using tcpdump. Write `datasets/manifests/<scenario>.json` with image digests, OpenSSL/TShark versions, cert metadata, capture hash, actual negotiated outcome and expected rule findings. Negative tests include TLS1.3 encrypted certificate, failed handshake, no STARTTLS advertisement, malformed and truncated captures. Never expose intentionally weak services to the public network.

## 9. Evaluation
Unit tests for protocol state machines and scoring; golden PCAP integration tests against TShark; end-to-end upload→finding→report; fuzz/malformed capture tests; performance on measured sample sizes. Split ML data by scenario run/server config to prevent near-duplicate leakage. Report precision, recall, false positive rate and confusion matrix where labels support them. Preserve both rules-only and ML-assisted baselines.

## 10. Repository layout
```text
frontend/src/{components,pages,features,services,types}
backend/app/{api,core,models,schemas,services,workers}
backend/app/services/{capture,pcap,protocols,tls,certificates,risk,ml,reports}
backend/tests/
ml/{training,evaluation,models}
synthetic-lab/{postfix,dovecot,scenarios,scripts}
datasets/{manifests,samples}
docs/{PRD.md,architecture.md,design.md}
```
Large PCAPs, secrets, key logs, `.env`, model artifacts and reports are ignored by Git unless intentionally sanitized and approved.

## 11. Finding Intelligence & Correlation Layer (G4.1)

### Overview & Data Flow
The G4.1 Finding Intelligence layer provides a deterministic, explainable correlation layer built directly above existing persisted `Finding`, `SecurityEvent`, `Session`, `Capture`, and `Investigation` records.
```text
Persisted DB Entities (Findings, SecurityEvents, Sessions)
       ↓
Intelligence Service (Deterministic Aggregation & Pattern Engine)
       ↓
GET /api/v1/investigations/{id}/intelligence
       ↓
React Security Intelligence Panel
```

### Core Epistemic Boundaries
- **No PCAP Reprocessing**: The intelligence engine NEVER invokes TShark or re-parses packet captures. It operates exclusively on persisted relational metadata.
- **No Speculative ML / LLM**: Intelligence findings are 100% deterministic and explainable without probabilistic ML or external AI calls.
- **Evidence Provenance Preservation**: Every generated insight references exact `supporting_finding_ids`, `supporting_session_ids`, `supporting_event_ids`, and `supporting_frame_numbers`.
- **No False Positive Claims**: Single rule occurrences do NOT generate "repeated" pattern insights. INFO baseline findings (`TLS-SECURE-BASELINE-001`) are excluded from security risk insights.

### Correlation Rules & Deterministic Identifiers
1. `INTEL-REPEATED-PLAINTEXT-001`: Triggered when `EMAIL-PLAINTEXT-NOT-OFFERED-001` affects $\ge 2$ sessions in the investigation.
2. `INTEL-REPEATED-STARTTLS-BYPASS-001`: Triggered when `EMAIL-STARTTLS-OFFERED-NOT-USED-001` affects $\ge 2$ sessions.
3. `INTEL-REPEATED-WEAK-CRYPTO-001`: Triggered when `TLS-WEAK-STATIC-RSA-001` affects $\ge 2$ sessions.
4. `INTEL-REPEATED-CERT-FAILURE-001`: Triggered when `TLS-ALERT-CERT-OBSERVED-001` affects $\ge 2$ sessions.
5. `INTEL-REPEATED-TLS-FAILURE-001`: Triggered when `TLS-HANDSHAKE-FAILED-001` affects $\ge 2$ sessions.

### Deterministic Risk, Severity, and Confidence Semantics
- **Insight Severity**: Defined as `max(severity)` among supporting active findings (`CRITICAL > HIGH > MEDIUM > LOW > INFO`).
- **Insight Risk Score**: Defined as `max(risk_score)` among supporting active findings.
- **Insight Confidence**: `HIGH` if supported by multiple sessions ($\ge 2$); `MEDIUM` if supported by a single strong finding; `LOW` if evidence is incomplete.
- **Evidence State**: Marked `INCOMPLETE` if any supporting finding contains incomplete evidence metadata; otherwise `OBSERVED`.

### API Endpoint
`GET /api/v1/investigations/{investigation_id}/intelligence`
- **200 OK**: Returns structured `InvestigationIntelligenceResponse` containing `risk_summary`, `protocol_exposure`, `pattern_summary`, and prioritized `insights`.
- **404 Not Found**: Returned for non-existent investigation IDs.
- **200 OK (Empty)**: Returned for investigations without findings with empty insights array and zeroed metrics.
