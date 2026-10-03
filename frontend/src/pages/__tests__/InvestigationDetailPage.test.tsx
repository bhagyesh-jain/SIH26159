import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { InvestigationDetailPage } from "../InvestigationDetailPage";
import * as investigationsApi from "../../api/investigations";
import * as sessionsApi from "../../api/sessions";
import * as findingsApi from "../../api/findings";
import { InvestigationSummaryResponse } from "../../types/api";

vi.mock("../../api/investigations");
vi.mock("../../api/sessions");
vi.mock("../../api/findings");

describe("InvestigationDetailPage Integration Tests", () => {
  const mockInv = {
    id: "inv_detail_01",
    title: "SOC Integration Test Case",
    status: "ACTIVE",
    created_at: "2026-10-04T02:00:00Z",
  };

  const mockSummary: InvestigationSummaryResponse = {
    investigation_id: "inv_detail_01",
    title: "SOC Integration Test Case",
    status: "ACTIVE",
    created_at: "2026-10-04T02:00:00Z",
    totals: {
      captures_count: 1,
      sessions_count: 2,
      total_findings_count: 2,
      actionable_findings_count: 2,
      informational_findings_count: 0,
      suppressed_findings_count: 0,
      resolved_findings_count: 0,
      affected_sessions_count: 2,
      highest_risk_score: 100,
    },
    severity_breakdown: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
    protocol_breakdown: { smtp_sessions: 2, imap_sessions: 0, pop3_sessions: 0, unknown_sessions: 0 },
    security_posture: {
      plaintext_not_offered_sessions: 1,
      starttls_offered_not_used_sessions: 1,
      weak_static_rsa_sessions: 0,
      certificate_alert_sessions: 0,
      handshake_failed_sessions: 0,
      secure_baseline_sessions: 0,
    },
    evidence_quality: {
      complete_sessions: 2,
      incomplete_sessions: 0,
      high_confidence_findings: 2,
      medium_confidence_findings: 0,
      low_or_unknown_confidence_findings: 0,
    },
  };

  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("1. Renders investigation details and SOC overview metrics from API", async () => {
    vi.mocked(investigationsApi.getInvestigation).mockResolvedValue(mockInv);
    vi.mocked(investigationsApi.getInvestigationSummary).mockResolvedValue(mockSummary);
    vi.mocked(sessionsApi.listInvestigationSessions).mockResolvedValue([]);
    vi.mocked(findingsApi.getInvestigationFindings).mockResolvedValue([]);

    render(
      <MemoryRouter initialEntries={["/investigations/inv_detail_01"]}>
        <Routes>
          <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("SOC Integration Test Case")).toBeInTheDocument();
    expect(await screen.findByText("Cryptographic Security Posture Breakdown")).toBeInTheDocument();
    expect(screen.getByText("Highest Risk Priority")).toBeInTheDocument();
    expect(screen.getByText("100")).toBeInTheDocument();
  });

  it("2. Displays error banner when investigation summary fails", async () => {
    vi.mocked(investigationsApi.getInvestigation).mockResolvedValue(mockInv);
    vi.mocked(investigationsApi.getInvestigationSummary).mockRejectedValue(new Error("Summary fetch failed"));
    vi.mocked(sessionsApi.listInvestigationSessions).mockResolvedValue([]);
    vi.mocked(findingsApi.getInvestigationFindings).mockResolvedValue([]);

    render(
      <MemoryRouter initialEntries={["/investigations/inv_detail_01"]}>
        <Routes>
          <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText(/Failed to load investigation summary: Summary fetch failed/i)).toBeInTheDocument();
  });
});
