import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { CaptureDetailModal } from "../CaptureDetailModal";
import { CaptureResponse } from "../../../types/api";

describe("CaptureDetailModal Component Tests", () => {
  const mockCapture: CaptureResponse = {
    id: "cap_001",
    investigation_id: "inv_001",
    filename: "SCN-SMTP-03.pcap",
    sha256: "9e4a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a",
    bytes: 307200,
    format: "PCAP",
    uploaded_at: "2026-10-04T01:30:00Z",
    job_id: "job_789",
    status: "COMPLETED",
    sessions_count: 4,
  };

  it("does not render when capture is null", () => {
    const { container } = render(
      <CaptureDetailModal capture={null} onClose={vi.fn()} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders full capture metadata, SHA-256 hash, and lifecycle info", () => {
    render(<CaptureDetailModal capture={mockCapture} onClose={vi.fn()} />);

    expect(screen.getByText("Capture Provenance Details")).toBeInTheDocument();
    expect(screen.getByText("cap_001")).toBeInTheDocument();
    expect(screen.getByText("SCN-SMTP-03.pcap")).toBeInTheDocument();
    expect(screen.getByText("inv_001")).toBeInTheDocument();
    expect(screen.getByText("job_789")).toBeInTheDocument();
    expect(
      screen.getByText("9e4a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a")
    ).toBeInTheDocument();
    expect(screen.getByText("4 Forensic Sessions Extracted")).toBeInTheDocument();
  });

  it("calls onClose when close button is clicked", () => {
    const onClose = vi.fn();
    render(<CaptureDetailModal capture={mockCapture} onClose={onClose} />);

    const closeButtons = screen.getAllByRole("button", { name: /Close/i });
    fireEvent.click(closeButtons[0]);

    expect(onClose).toHaveBeenCalled();
  });

  it("calls onNavigateToSessions when View Sessions button is clicked", () => {
    const onNavigate = vi.fn();
    const onClose = vi.fn();
    render(
      <CaptureDetailModal
        capture={mockCapture}
        onClose={onClose}
        onNavigateToSessions={onNavigate}
      />
    );

    const viewSessionsBtn = screen.getByRole("button", { name: /View Sessions/i });
    fireEvent.click(viewSessionsBtn);

    expect(onClose).toHaveBeenCalled();
    expect(onNavigate).toHaveBeenCalledWith("cap_001");
  });
});
