import { describe, it, expect } from "vitest";
import { FindingResponse } from "../api";

describe("FindingResponse Contract Tests", () => {
  it("3. FindingResponse preserves severity, confidence, risk_score, evidence_event_ids, and evidence_frame_numbers as native arrays", () => {
    const mockFinding: FindingResponse = {
      id: "fnd_9a3c10b48e2a",
      investigation_id: "inv_410a51c91f0d",
      session_id: "sess_smtp_03_s1",
      rule_id: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
      title: "Plaintext Transmission Despite Advertised Encryption Capability",
      description: "Server advertised SMTP encryption upgrade capability, but client sent unencrypted traffic.",
      severity: "CRITICAL",
      confidence: "HIGH",
      risk_score: 100,
      status: "ACTIVE",
      protocol: "SMTP",
      observed_value: "MAIL FROM:<sender@lab.local>",
      evidence_event_ids: ["sevt_1d8e4f", "sevt_3b9a2c"],
      evidence_frame_numbers: [8, 9],
      first_seen: "2026-10-04T02:00:00Z",
      last_seen: "2026-10-04T02:00:01Z",
      details: {
        credential_exposure_observed: false,
        what: "Plaintext commands transmitted after encryption capability offer.",
      },
    };

    expect(mockFinding.severity).toBe("CRITICAL");
    expect(mockFinding.confidence).toBe("HIGH");
    expect(mockFinding.risk_score).toBe(100);
    expect(Array.isArray(mockFinding.evidence_event_ids)).toBe(true);
    expect(mockFinding.evidence_event_ids).toEqual(["sevt_1d8e4f", "sevt_3b9a2c"]);
    expect(Array.isArray(mockFinding.evidence_frame_numbers)).toBe(true);
    expect(mockFinding.evidence_frame_numbers).toEqual([8, 9]);
  });
});
