import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { InvestigationsListPage } from "../InvestigationsListPage";
import * as invApi from "../../api/investigations";
import { InvestigationResponse } from "../../types/api";

vi.mock("../../api/investigations");

describe("InvestigationsListPage Component Tests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("1. Investigation list loading state renders during API fetch", () => {
    vi.spyOn(invApi, "listInvestigations").mockReturnValue(new Promise(() => {}));

    render(
      <BrowserRouter>
        <InvestigationsListPage />
      </BrowserRouter>
    );

    expect(screen.getByText("Loading active forensic investigation cases...")).toBeInTheDocument();
  });

  it("2. Empty investigation state renders when API returns empty list", async () => {
    vi.spyOn(invApi, "listInvestigations").mockResolvedValue([]);

    render(
      <BrowserRouter>
        <InvestigationsListPage />
      </BrowserRouter>
    );

    expect(await screen.findByText("No Active Investigations")).toBeInTheDocument();
  });

  it("Renders investigation cards when data is returned from API", async () => {
    const mockInvs: InvestigationResponse[] = [
      {
        id: "inv_case_001",
        title: "SMTP TLS Exfiltration Benchmark",
        created_at: "2026-10-04T02:00:00Z",
        status: "ACTIVE",
      },
    ];

    vi.spyOn(invApi, "listInvestigations").mockResolvedValue(mockInvs);

    render(
      <BrowserRouter>
        <InvestigationsListPage />
      </BrowserRouter>
    );

    expect(await screen.findByText("SMTP TLS Exfiltration Benchmark")).toBeInTheDocument();
    expect(screen.getByText("inv_case_001")).toBeInTheDocument();
  });
});
