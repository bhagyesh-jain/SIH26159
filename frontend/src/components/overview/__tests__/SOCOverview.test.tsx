import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect } from "vitest";
import { OverviewMetricCards } from "../OverviewMetricCards";
import { SecurityPostureGrid } from "../SecurityPostureGrid";
import { SeverityDistributionBar } from "../SeverityDistributionBar";
import { EvidenceQualityPanel } from "../EvidenceQualityPanel";
import { TopFindingsCard } from "../TopFindingsCard";
import { InvestigationSummaryResponse, FindingResponse } from "../../../types/api";

describe("SOC Overview Component Tests", () => {
  const mockSummary: InvestigationSummaryResponse = {
    investigation_id: "inv_test_01",
    title: "SOC Overview Test Case",
    status: "ACTIVE",
    created_at: "2026-10-04T02:00:00Z",
    totals: {
      captures_count: 1,
      sessions_count: 5,
      total_findings_count: 4,
      actionable_findings_count: 3,
      informational_findings_count: 1,
      suppressed_findings_count: 0,
      resolved_findings_count: 0,
      affected_sessions_count: 2,
      highest_risk_score: 100,
    },
    severity_breakdown: {
      critical: 1,
      high: 2,
      medium: 0,
      low: 0,
      info: 1,
    },
    protocol_breakdown: {
      smtp_sessions: 3,
      imap_sessions: 1,
      pop3_sessions: 1,
      unknown_sessions: 0,
    },
    security_posture: {
      plaintext_not_offered_sessions: 1,
      starttls_offered_not_used_sessions: 1,
      weak_static_rsa_sessions: 1,
      certificate_alert_sessions: 0,
      handshake_failed_sessions: 0,
      secure_baseline_sessions: 1,
    },
    evidence_quality: {
      complete_sessions: 5,
      incomplete_sessions: 0,
      high_confidence_findings: 4,
      medium_confidence_findings: 0,
      low_or_unknown_confidence_findings: 0,
    },
  };

  const mockFindings: FindingResponse[] = [
    {
      id: "fnd_01",
      investigation_id: "inv_test_01",
      session_id: "sess_01",
      rule_id: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
      title: "Plaintext Transmission Despite Advertised Encryption Capability",
      description: "STARTTLS offered but not used",
      severity: "CRITICAL",
      confidence: "HIGH",
      risk_score: 100,
      status: "ACTIVE",
      protocol: "SMTP",
      observed_value: "250-STARTTLS",
      evidence_event_ids: ["sevt_01"],
      evidence_frame_numbers: [8],
    },
  ];

  it("1. OverviewMetricCards renders correct metrics and risk score", () => {
    render(
      <OverviewMetricCards
        totals={mockSummary.totals}
        protocolBreakdown={mockSummary.protocol_breakdown}
      />
    );

    expect(screen.getByText("5")).toBeInTheDocument(); // sessions_count
    expect(screen.getByText("3")).toBeInTheDocument(); // actionable_findings_count
    expect(screen.getByText("100")).toBeInTheDocument(); // highest_risk_score
    expect(screen.getByText("1")).toBeInTheDocument(); // informational_findings_count
    expect(screen.getByText((_, element) => element?.textContent === "Affecting 2 sessions")).toBeInTheDocument();
  });

  it("2. SecurityPostureGrid renders rule session counts", () => {
    render(<SecurityPostureGrid posture={mockSummary.security_posture} />);

    expect(screen.getByText("EMAIL-STARTTLS-OFFERED-NOT-USED-001")).toBeInTheDocument();
    expect(screen.getByText("EMAIL-PLAINTEXT-NOT-OFFERED-001")).toBeInTheDocument();
    expect(screen.getByText("TLS-WEAK-STATIC-RSA-001")).toBeInTheDocument();
  });

  it("3. SeverityDistributionBar renders visual severity breakdown", () => {
    render(<SeverityDistributionBar breakdown={mockSummary.severity_breakdown} />);

    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("INFO")).toBeInTheDocument();
    expect(screen.getByText("Total Active: 4")).toBeInTheDocument();
  });

  it("4. EvidenceQualityPanel renders completeness and confidence distribution", () => {
    render(<EvidenceQualityPanel evidenceQuality={mockSummary.evidence_quality} />);

    expect(screen.getByText("Complete Reassembled Streams:")).toBeInTheDocument();
    expect(screen.getByText("High Confidence (Direct Wire Evidence):")).toBeInTheDocument();
  });

  it("5. TopFindingsCard renders priority items with stream links", () => {
    render(
      <MemoryRouter>
        <TopFindingsCard findings={mockFindings} />
      </MemoryRouter>
    );

    expect(
      screen.getByText("Plaintext Transmission Despite Advertised Encryption Capability")
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Inspect Stream/i })).toBeInTheDocument();
  });
});
