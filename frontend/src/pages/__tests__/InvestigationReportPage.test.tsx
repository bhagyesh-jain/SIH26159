import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { InvestigationReportPage } from "../InvestigationReportPage";
import * as investigationsApi from "../../api/investigations";
import {
  InvestigationReportResponse,
  FindingResponse,
  SecurityEventResponse,
} from "../../types/api";

vi.mock("../../api/investigations");

describe("InvestigationReportPage Component Tests", () => {
  const mockFindings: FindingResponse[] = [
    {
      id: "fnd_crit_001",
      investigation_id: "inv_report_test_01",
      session_id: "sess_s1",
      rule_id: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
      title: "Plaintext Transmission Despite Advertised Encryption Capability",
      description: "STARTTLS was offered by server, but client transmitted unencrypted authentication payload [REDACTED].",
      severity: "CRITICAL",
      confidence: "HIGH",
      risk_score: 100,
      status: "ACTIVE",
      protocol: "SMTP",
      observed_value: "AUTH LOGIN [REDACTED]",
      evidence_event_ids: ["sevt_1"],
      evidence_frame_numbers: [8, 9],
      details: {
        credential_exposure_observed: true,
        remediation: "Mandate TLS before auth.",
      },
    },
    {
      id: "fnd_info_002",
      investigation_id: "inv_report_test_01",
      session_id: "sess_s2",
      rule_id: "TLS-SECURE-BASELINE-001",
      title: "Negotiated Modern TLS Session Security Baseline",
      description: "TLS 1.3 negotiated with PFS cipher suite.",
      severity: "INFO",
      confidence: "HIGH",
      risk_score: 0,
      status: "ACTIVE",
      protocol: "SMTP",
      observed_value: "TLS 1.3 | TLS_AES_256_GCM_SHA384",
      evidence_event_ids: ["sevt_2"],
      evidence_frame_numbers: [12],
    },
  ];

  const mockSecurityEvents: SecurityEventResponse[] = [
    {
      id: "sevt_1",
      session_id: "sess_s1",
      event_type: "PLAINTEXT_COMMAND_AFTER_OFFER",
      protocol: "SMTP",
      upgrade_status: "OFFERED_NOT_USED",
      observed_value: "AUTH LOGIN [REDACTED]",
      frame_numbers: [8, 9],
      evidence_source: "TSHARK_REASSEMBLED_STREAM",
      completeness_status: "COMPLETE",
    },
  ];

  const mockReport: InvestigationReportResponse = {
    investigation_id: "inv_report_test_01",
    title: "Corporate Email Security Forensic Case",
    status: "ACTIVE",
    created_at: "2026-10-04T02:00:00Z",
    generated_at: "2026-10-04T02:05:00Z",
    evidence_scope: "COMPLETE",
    summary: {
      investigation_id: "inv_report_test_01",
      title: "Corporate Email Security Forensic Case",
      status: "ACTIVE",
      created_at: "2026-10-04T02:00:00Z",
      totals: {
        captures_count: 1,
        sessions_count: 2,
        total_findings_count: 2,
        actionable_findings_count: 1,
        informational_findings_count: 1,
        suppressed_findings_count: 0,
        resolved_findings_count: 0,
        affected_sessions_count: 1,
        highest_risk_score: 100,
      },
      severity_breakdown: {
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        info: 1,
      },
      protocol_breakdown: {
        smtp_sessions: 2,
        imap_sessions: 0,
        pop3_sessions: 0,
        unknown_sessions: 0,
      },
      security_posture: {
        plaintext_not_offered_sessions: 0,
        starttls_offered_not_used_sessions: 1,
        weak_static_rsa_sessions: 0,
        certificate_alert_sessions: 0,
        handshake_failed_sessions: 0,
        secure_baseline_sessions: 1,
      },
      evidence_quality: {
        complete_sessions: 2,
        incomplete_sessions: 0,
        high_confidence_findings: 2,
        medium_confidence_findings: 0,
        low_or_unknown_confidence_findings: 0,
      },
    },
    findings: mockFindings,
    security_events: mockSecurityEvents,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("1. Renders complete investigation report identity, executive summary, posture, and Evidence Scope COMPLETE", async () => {
    vi.spyOn(investigationsApi, "getInvestigationReport").mockResolvedValue(mockReport);

    render(
      <MemoryRouter initialEntries={["/investigations/inv_report_test_01/report"]}>
        <Routes>
          <Route path="/investigations/:id/report" element={<InvestigationReportPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("FORENSIC INVESTIGATION REPORT")).toBeInTheDocument();
    expect(screen.getAllByText("Corporate Email Security Forensic Case").length).toBeGreaterThan(0);
    expect(screen.getByText("inv_report_test_01")).toBeInTheDocument();
    expect(screen.getAllByText(/Evidence scope:\s*COMPLETE/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Executive Security Summary")).toBeInTheDocument();
    expect(screen.getByText("Assessment Methodology & Forensic Limitations")).toBeInTheDocument();
  });

  it("2. Findings are ordered deterministically by backend and expose epistemic labels", async () => {
    vi.spyOn(investigationsApi, "getInvestigationReport").mockResolvedValue(mockReport);

    render(
      <MemoryRouter initialEntries={["/investigations/inv_report_test_01/report"]}>
        <Routes>
          <Route path="/investigations/:id/report" element={<InvestigationReportPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("Plaintext Transmission Despite Advertised Encryption Capability")).toBeInTheDocument();
    expect(screen.getByText("OBSERVED EVIDENCE")).toBeInTheDocument();
    expect(screen.getByText("OBSERVED BASELINE")).toBeInTheDocument();

    const titles = screen.getAllByRole("heading", { level: 3 });
    expect(titles[0].textContent).toContain("Plaintext Transmission Despite Advertised Encryption Capability");
    expect(titles[1].textContent).toContain("Negotiated Modern TLS Session Security Baseline");
  });

  it("3. Credential redaction remains intact in report observed values", async () => {
    vi.spyOn(investigationsApi, "getInvestigationReport").mockResolvedValue(mockReport);

    render(
      <MemoryRouter initialEntries={["/investigations/inv_report_test_01/report"]}>
        <Routes>
          <Route path="/investigations/:id/report" element={<InvestigationReportPage />} />
        </Routes>
      </MemoryRouter>
    );

    const redactedElements = await screen.findAllByText("AUTH LOGIN [REDACTED]");
    expect(redactedElements.length).toBeGreaterThan(0);
  });

  it("4. Empty investigation with no findings renders clean report state without crashing", async () => {
    vi.spyOn(investigationsApi, "getInvestigationReport").mockResolvedValue({
      ...mockReport,
      evidence_scope: "COMPLETE",
      findings: [],
      security_events: [],
    });

    render(
      <MemoryRouter initialEntries={["/investigations/inv_report_test_01/report"]}>
        <Routes>
          <Route path="/investigations/:id/report" element={<InvestigationReportPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("FORENSIC INVESTIGATION REPORT")).toBeInTheDocument();
    expect(screen.getByText("No security findings identified in analyzed capture streams.")).toBeInTheDocument();
  });
});

