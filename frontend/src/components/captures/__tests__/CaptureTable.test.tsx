import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { CaptureTable } from "../CaptureTable";
import { CaptureResponse } from "../../../types/api";

describe("CaptureTable Component Tests", () => {
  const mockCaptures: CaptureResponse[] = [
    {
      id: "cap_001",
      investigation_id: "inv_001",
      filename: "SCN-SMTP-01.pcap",
      sha256: "9e4a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a",
      bytes: 204800,
      format: "PCAP",
      uploaded_at: "2026-10-04T01:00:00Z",
      status: "COMPLETED",
      sessions_count: 2,
    },
    {
      id: "cap_002",
      investigation_id: "inv_001",
      filename: "SCN-SMTP-02.pcap",
      sha256: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
      bytes: 102400,
      format: "PCAPNG",
      uploaded_at: "2026-10-04T01:05:00Z",
      status: "FAILED",
      sessions_count: 0,
    },
  ];

  it("renders empty state when no captures are provided", () => {
    render(<CaptureTable captures={[]} />);
    expect(screen.getByText(/No source capture files uploaded for this investigation case/i)).toBeInTheDocument();
  });

  it("renders loading state", () => {
    render(<CaptureTable captures={[]} loading={true} />);
    expect(screen.getByText(/Loading source capture files and evidence provenance/i)).toBeInTheDocument();
  });

  it("renders capture items with SHA-256 and formatted attributes", () => {
    render(<CaptureTable captures={mockCaptures} />);

    expect(screen.getByText("cap_001")).toBeInTheDocument();
    expect(screen.getByText("SCN-SMTP-01.pcap")).toBeInTheDocument();
    expect(screen.getByText("PCAP")).toBeInTheDocument();
    expect(screen.getByText("200.0 KB")).toBeInTheDocument();
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();

    expect(screen.getByText("cap_002")).toBeInTheDocument();
    expect(screen.getByText("SCN-SMTP-02.pcap")).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
  });

  it("triggers onSelectCapture when row or details button is clicked", () => {
    const onSelect = vi.fn();
    render(<CaptureTable captures={mockCaptures} onSelectCapture={onSelect} />);

    const detailsBtns = screen.getAllByRole("button", { name: /Details/i });
    fireEvent.click(detailsBtns[0]);

    expect(onSelect).toHaveBeenCalledWith(mockCaptures[0]);
  });
});
