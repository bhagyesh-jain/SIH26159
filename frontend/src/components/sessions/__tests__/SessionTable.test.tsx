import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { describe, it, expect } from "vitest";
import { SessionTable } from "../SessionTable";
import { SessionResponse } from "../../../types/api";

describe("SessionTable Component Tests", () => {
  it("10. Session table renders backend session data accurately", () => {
    const mockSessions: SessionResponse[] = [
      {
        id: "sess_smtp_01",
        capture_id: "cap_10",
        tcp_stream: 0,
        src: "10.0.0.1",
        src_port: 52140,
        dst: "10.0.0.2",
        dst_port: 25,
        protocol: "SMTP",
        completeness: "COMPLETE",
        events_count: 7,
      },
    ];

    render(
      <BrowserRouter>
        <SessionTable sessions={mockSessions} />
      </BrowserRouter>
    );

    expect(screen.getByText("Stream #0")).toBeInTheDocument();
    expect(screen.getByText("SMTP")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1:52140")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2:25")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
  });

  it("11. Session links use the correct session ID for navigation", () => {
    const mockSessions: SessionResponse[] = [
      {
        id: "sess_target_abc999",
        capture_id: "cap_10",
        tcp_stream: 3,
        src: "192.168.1.5",
        src_port: 44100,
        dst: "192.168.1.10",
        dst_port: 143,
        protocol: "IMAP",
        completeness: "COMPLETE",
        events_count: 12,
      },
    ];

    render(
      <BrowserRouter>
        <SessionTable sessions={mockSessions} />
      </BrowserRouter>
    );

    const link = screen.getByRole("link", { name: /View Timeline/i });
    expect(link).toHaveAttribute("href", "/sessions/sess_target_abc999");
  });
});
