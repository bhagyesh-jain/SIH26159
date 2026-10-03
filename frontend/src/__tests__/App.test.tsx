import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import App from "../App";

// Mock API call in SOCLayout
vi.mock("../api/health", () => ({
  getHealthStatus: vi.fn().mockResolvedValue({
    status: "healthy",
    tshark: { available: true, version: "3.6.2" },
  }),
}));

describe("App Route Rendering Tests", () => {
  it("6. App renders header logo and navigates to default investigations page", async () => {
    render(<App />);

    expect(await screen.findByText("SecureMailScope")).toBeInTheDocument();
    expect(await screen.findByText("Forensic Investigations")).toBeInTheDocument();
  });
});

