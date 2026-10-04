import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { SecurityIntelligencePanel } from "../SecurityIntelligencePanel";
import { InvestigationIntelligenceResponse } from "../../../types/api";

describe("SecurityIntelligencePanel Component Tests", () => {
  const mockIntelligence: InvestigationIntelligenceResponse = {
    investigation_id: "inv_intel_test_01",
    generated_at: "2026-10-04T03:00:00Z",
    risk_summary: {
      highest_risk_score: 100,
      highest_risk_finding_id: "fnd_crit_100",
      highest_risk_session_id: "sess_s1",
      active_findings_count: 4,
      affected_sessions_count: 3,
      risk_concentration: {
        "EMAIL-STARTTLS-OFFERED-NOT-USED-001": 2,
        "EMAIL-PLAINTEXT-NOT-OFFERED-001": 2,
      },
    },
    protocol_exposure: [
      {
        protocol: "SMTP",
        total_sessions: 3,
        affected_sessions: 3,
        active_findings_count: 4,
        highest_risk_score: 100,
        severity_breakdown: { critical: 4, high: 0, medium: 0, low: 0, info: 0 },
        dominant_rule_id: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
      },
      {
        protocol: "IMAP",
        total_sessions: 0,
        affected_sessions: 0,
        active_findings_count: 0,
        highest_risk_score: 0,
        severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        dominant_rule_id: null,
      },
      {
        protocol: "POP3",
        total_sessions: 0,
        affected_sessions: 0,
        active_findings_count: 0,
        highest_risk_score: 0,
        severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        dominant_rule_id: null,
      },
    ],
    pattern_summary: {
      repeated_rules: [
        "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
        "EMAIL-PLAINTEXT-NOT-OFFERED-001",
      ],
      affected_protocols: ["SMTP"],
      affected_sessions_count: 3,
    },
    insights: [
      {
        id: "INTEL-REPEATED-STARTTLS-BYPASS-001",
        title: "Repeated STARTTLS Encryption Bypass Observed",
        description:
          "STARTTLS upgrade capabilities were advertised by servers but unencrypted traffic was transmitted across 2 distinct sessions.",
        severity: "CRITICAL",
        confidence: "HIGH",
        risk_score: 100,
        evidence_state: "OBSERVED",
        supporting_finding_ids: ["fnd_b1", "fnd_b2"],
        supporting_session_ids: ["sess_s1", "sess_s2"],
        supporting_event_ids: ["evt_1", "evt_2"],
        supporting_frame_numbers: [10, 14],
        remediation: "Mandate TLS before auth.",
      },
    ],
  };

  it("renders loading state", () => {
    render(<SecurityIntelligencePanel intelligence={null} loading={true} />);
    expect(
      screen.getByText(/Calculating deterministic security intelligence & correlation patterns/i)
    ).toBeInTheDocument();
  });

  it("renders error state", () => {
    const onRetry = vi.fn();
    render(
      <SecurityIntelligencePanel
        intelligence={null}
        error="Failed to load intelligence"
        onRetry={onRetry}
      />
    );
    expect(screen.getByText("Intelligence Generation Failed")).toBeInTheDocument();
    expect(screen.getByText("Failed to load intelligence")).toBeInTheDocument();
  });

  it("renders risk summary metrics and protocol exposure matrix", () => {
    render(
      <MemoryRouter>
        <SecurityIntelligencePanel intelligence={mockIntelligence} />
      </MemoryRouter>
    );

    expect(screen.getByText("Security Intelligence & Correlation Layer")).toBeInTheDocument();
    expect(screen.getByText("100 / 100")).toBeInTheDocument();
    expect(screen.getByText("EMAIL-STARTTLS-OFFERED-NOT-USED-001")).toBeInTheDocument();
  });

  it("renders priority insights with severity, confidence, evidence state, and session link", () => {
    render(
      <MemoryRouter>
        <SecurityIntelligencePanel intelligence={mockIntelligence} />
      </MemoryRouter>
    );

    expect(
      screen.getByText("Repeated STARTTLS Encryption Bypass Observed")
    ).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("HIGH CONFIDENCE")).toBeInTheDocument();
    expect(screen.getByText("OBSERVED EVIDENCE")).toBeInTheDocument();
    expect(screen.getByText("Mandate TLS before auth.")).toBeInTheDocument();
    expect(screen.getByText("Inspect Supporting Session")).toBeInTheDocument();
  });

  it("renders empty state when insights array is empty", () => {
    render(
      <MemoryRouter>
        <SecurityIntelligencePanel
          intelligence={{
            ...mockIntelligence,
            insights: [],
          }}
        />
      </MemoryRouter>
    );

    expect(
      screen.getByText(/No repeated correlation patterns detected across active investigation sessions/i)
    ).toBeInTheDocument();
  });
});
