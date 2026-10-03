import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { FindingDetailPanel } from "../FindingDetailPanel";
import { FindingResponse } from "../../../types/api";

describe("FindingDetailPanel Component Tests", () => {
  const mockFinding: FindingResponse = {
    id: "fnd_test_001",
    investigation_id: "inv_001",
    session_id: "sess_001",
    rule_id: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
    title: "Plaintext Transmission Despite Advertised Encryption Capability",
    description: "Server advertised encryption capability, but client transmitted unencrypted traffic.",
    severity: "CRITICAL",
    confidence: "HIGH",
    risk_score: 100,
    status: "ACTIVE",
    protocol: "SMTP",
    observed_value: "MAIL FROM:<sender@lab.local>",
    evidence_event_ids: ["sevt_1d8e4f", "sevt_unresolved_99"],
    evidence_frame_numbers: [8, 9],
    first_seen: "2026-10-04T02:00:00Z",
    last_seen: "2026-10-04T02:00:01Z",
    details: {
      credential_exposure_observed: false,
      remediation: "Mandate TLS upgrade before auth.",
    },
  };

  it("4. Finding severity, confidence, and risk score are displayed exactly as supplied by backend", () => {
    render(
      <FindingDetailPanel
        finding={mockFinding}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("HIGH CONFIDENCE")).toBeInTheDocument();
    expect(screen.getByText("100 / 100")).toBeInTheDocument();
    expect(screen.getByText("EMAIL-STARTTLS-OFFERED-NOT-USED-001")).toBeInTheDocument();
  });

  it("5 & 6. Finding evidence frame numbers and event IDs render visibly", () => {
    render(
      <FindingDetailPanel
        finding={mockFinding}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText("Frame #8")).toBeInTheDocument();
    expect(screen.getByText("Frame #9")).toBeInTheDocument();
    expect(screen.getByText("sevt_1d8e4f")).toBeInTheDocument();
    expect(screen.getByText("sevt_unresolved_99")).toBeInTheDocument();
  });

  it("8 & 9. Selecting evidence frame triggers callback; unresolved evidence IDs are preserved visibly", () => {
    const onSelectFrame = vi.fn();

    render(
      <FindingDetailPanel
        finding={mockFinding}
        onClose={vi.fn()}
        onSelectFrame={onSelectFrame}
      />
    );

    const frameBtn = screen.getByText("Frame #8");
    fireEvent.click(frameBtn);

    expect(onSelectFrame).toHaveBeenCalledWith(8);
    // Verify unresolved ID remains visible in UI
    expect(screen.getByText("sevt_unresolved_99")).toBeInTheDocument();
  });
});
