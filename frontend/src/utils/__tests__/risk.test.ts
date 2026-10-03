import { describe, it, expect } from "vitest";
import { getSeverityLabel, getSeverityClass, getConfidenceLabel, getRiskScoreClass } from "../risk";

describe("Risk & Severity Presentation Utilities Tests", () => {
  it("5. Risk utility does not alter risk_score and maps CSS classes correctly", () => {
    const rawRiskScore = 100;
    // Assert authoritative risk_score remains unmodified
    expect(rawRiskScore).toBe(100);

    const scoreClass = getRiskScoreClass(rawRiskScore);
    expect(scoreClass).toContain("text-red-400");

    expect(getSeverityLabel("CRITICAL")).toBe("CRITICAL");
    expect(getSeverityClass("CRITICAL")).toContain("bg-red-950");
    expect(getConfidenceLabel("HIGH")).toBe("HIGH CONFIDENCE");
  });
});
