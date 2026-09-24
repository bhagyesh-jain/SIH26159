# SecureMailScope — Product Requirements Document

**Project:** SIH 2026 / SIH26159  
**Problem owner:** National Technical Research Organisation (NTRO)  
**Repository:** https://github.com/bhagyesh-jain/SIH26159  
**Status:** Proposed v1.0; validate implementation and dependencies during Phase 0.

## 1. Product vision
SecureMailScope is a local-first, AI-assisted passive network forensic application for assessing the cryptographic security posture of captured SMTP, IMAP and POP3 communications. It accepts authorized PCAP/PCAPNG captures, reconstructs observable sessions, examines TLS/STARTTLS negotiations, generates evidence-backed findings, flags anomalous behavior and produces investigation-ready reports.

**Non-goals:** decrypting traffic without authorized keys, collecting real inbox contents, live interception, offensive exploitation, claiming unavailable TLS 1.3 certificate details from passive captures, or treating an ML anomaly as proof of compromise.

## 2. Users and key workflows
- SOC analyst: upload capture, triage findings, inspect packet evidence, export report.
- Forensic investigator: preserve capture hash, investigate TCP stream timeline, document evidence and limitations.
- Email administrator: identify obsolete TLS, certificate issues and remediation actions.
- SIH evaluator: reproduce a controlled synthetic scenario and verify observed findings.

Primary workflow: create investigation → upload PCAP → validate/hash → queue analysis → identify streams/protocols → reconstruct observable STARTTLS/TLS events → apply rules → run optional ML → review findings and evidence → export report.

## 3. Functional requirements
| ID | Requirement | Priority | Acceptance evidence |
|---|---|---|---|
| FR-01 | Create investigations and upload PCAP/PCAPNG | P0 | Valid capture accepted; malformed/oversized rejected |
| FR-02 | SHA-256 hash, metadata and immutable original | P0 | Hash matches local calculation |
| FR-03 | Extract TCP streams and endpoints via TShark | P0 | Stream/packet references agree with TShark |
| FR-04 | Identify SMTP/IMAP/POP3 using protocol evidence, not ports alone | P0 | Known synthetic samples classified; uncertain labelled unknown |
| FR-05 | Identify SMTP STARTTLS transition and outcome | P0 | Timeline links commands/responses and handshake packets |
| FR-06 | Extract observable TLS handshake version, negotiated cipher and alerts | P0 | Agrees with TShark for complete supported samples |
| FR-07 | Rule-based cryptographic findings with packet evidence | P0 | Each finding has rule ID, severity, confidence, packet/stream refs |
| FR-08 | Investigation and session dashboard | P1 | Filter/search and drill down to evidence |
| FR-09 | IMAP STARTTLS and POP3 STLS support | P1 | Lab scenario tests pass |
| FR-10 | Certificate extraction and validation where evidence permits | P1 | Trust assumptions and unavailable data explicit |
| FR-11 | Forward-secrecy assessment from negotiated suite/key exchange | P1 | Correct on controlled supported captures |
| FR-12 | JSON, HTML and PDF report export | P1 | All exports contain consistent finding IDs/evidence |
| FR-13 | Isolation Forest anomaly detection | P2 | Held-out evaluation with false-positive metrics |
| FR-14 | Transparent risk score and separate evidence coverage | P2 | Score methodology documented; unknown ≠ secure |
| FR-15 | Reproducible synthetic traffic lab | P0 | Manifest records config, expected and observed outcomes |

## 4. MVP boundaries
The first end-to-end vertical slice supports one locally generated SMTP STARTTLS PCAP: upload, hash, TShark extraction, stream identification, observable STARTTLS/TLS timeline, one deterministic finding, basic JSON response and minimal frontend evidence view. Expand only after automated and manual verification.

## 5. Forensic integrity and evidence model
Every result references capture ID/hash, stream ID, packet numbers, parser/tool versions, rule-set version and analysis timestamp. Store observed values separately from inferred conclusions and lab ground truth. Represent unavailable, incomplete, failed and not-applicable explicitly. A TLS 1.3 certificate is generally encrypted on the wire; authorized key-log-assisted decryption is an optional, separately identified mode.

## 6. Risk classification
Known cryptographic weaknesses use versioned deterministic rules. ML anomalies are separate advisory signals. Proposed 0–100 posture score must disclose weights, applicable checks, exclusions and assessment coverage; no score when evidence is insufficient. Findings have severity, confidence, evidence, rationale and actionable remediation. Do not describe synthetic scores as standardized compliance certification.

## 7. Synthetic data
Use isolated Docker Compose with Postfix, Dovecot, OpenSSL, test users and synthetic messages. Generate secure TLS 1.2/1.3, SMTP/IMAP/POP3 upgrades, unavailable STARTTLS, handshake failure, certificate expiration, self-signed certificates, static-RSA/no-forward-secrecy where supported and deliberately incomplete captures. Legacy TLS may require pinned older isolated images. No publicly exposed weak lab services. Store PCAPs, config manifests and observed negotiation labels; keep private keys and key logs out of Git.

## 8. Non-functional requirements
- Local-first operation; no third-party upload of raw evidence by default.
- Bounded upload size, bounded analysis time/memory and background job status.
- Safe TShark invocation with argument arrays, no shell interpolation, sandboxed worker and minimal privileges.
- Accessibility: keyboard navigation, readable tables, reduced motion, WCAG AA contrast target.
- Reproducibility: pinned tool/container versions, deterministic tests, documented environment.
- Performance target (initial, to benchmark): complete a representative 50 MB lab capture within 2 minutes on the team's development machine; report actual results rather than promising a guarantee.

## 9. Milestones and gates
**Phase 0 — Repository and environment:** docs approved; Git initialized; Python, Node and TShark checks; no app implementation before review.

**Phase 1 — Backend foundation:** FastAPI, upload validation, SHA-256, local storage, TShark adapter, tests. Gate: one PCAP returns verifiable stream JSON.

**Phase 2 — Synthetic lab and protocol parser:** reproducible SMTP/IMAP/POP3 scenarios, STARTTLS/STLS timeline, TLS handshake fields. Gate: golden PCAP assertions.

**Phase 3 — Rules and certificates:** explainable findings, conditional certificate validation, coverage semantics. Gate: positive/negative tests and packet citations.

**Phase 4 — Frontend:** investigations, session explorer, findings and basic report. Gate: complete vertical slice in browser with actual data.

**Phase 5 — ML and advanced reporting:** model training/evaluation, PDF/HTML exports, provenance and limitations. Gate: documented metrics and cross-format consistency.

**Phase 6 — Hardening and SIH demo:** malformed/large capture tests, repeatable demo, screenshots, technical explanation and known limitations.

## 10. Definition of done
All three protocols tested on controlled captures; observable TLS and upgrade behavior correctly reconstructed; verified cryptographic rules backed by packet evidence; missing data labelled unknown; reproducible synthetic lab; functional UI and consistent reports; documented ML metrics; no hard-coded demo findings presented as live analysis.

## 11. Decisions pending
Confirm Windows/WSL2 setup, preferred maximum capture size, team ownership, deployment target, exact versions and licensing of optional Bklit assets. Do not block the first local backend milestone on these decisions.
