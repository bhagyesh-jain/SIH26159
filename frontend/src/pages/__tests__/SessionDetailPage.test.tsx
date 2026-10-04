import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { SessionDetailPage } from "../SessionDetailPage";
import * as sessionsApi from "../../api/sessions";
import {
  SessionDetailResponse,
  FindingResponse,
  SecurityEventResponse,
} from "../../types/api";

vi.mock("../../api/sessions");

describe("SessionDetailPage Integration Tests", () => {
  const mockSession: SessionDetailResponse = {
    id: "sess_smtp_03_s1",
    capture_id: "cap_test_01",
    tcp_stream: 1,
    src: "10.0.0.1",
    src_port: 50123,
    dst: "10.0.0.2",
    dst_port: 25,
    protocol: "SMTP",
    completeness: "COMPLETE",
    events_count: 2,
    events: [
      {
        id: "evt_1",
        packet_number: 8,
        event_type: "CAPABILITY_ADVERTISED",
        timestamp: "2026-10-04T02:00:00Z",
        observed_json: "250-STARTTLS",
      },
      {
        id: "evt_2",
        packet_number: 9,
        event_type: "PLAINTEXT_COMMAND_AFTER_OFFER",
        timestamp: "2026-10-04T02:00:01Z",
        observed_json: "MAIL FROM:<sender@lab.local>",
      },
    ],
  };

  const mockFindings: FindingResponse[] = [
    {
      id: "fnd_001",
      investigation_id: "inv_001",
      session_id: "sess_smtp_03_s1",
      rule_id: "EMAIL-STARTTLS-OFFERED-NOT-USED-001",
      title: "Plaintext Transmission Despite Advertised Encryption Capability",
      description: "STARTTLS was offered but plaintext commands were sent.",
      severity: "CRITICAL",
      confidence: "HIGH",
      risk_score: 100,
      status: "ACTIVE",
      protocol: "SMTP",
      observed_value: "MAIL FROM:<sender@lab.local>",
      evidence_event_ids: ["sevt_1"],
      evidence_frame_numbers: [8, 9],
    },
  ];

  const mockSecEvents: SecurityEventResponse[] = [
    {
      id: "sevt_1",
      session_id: "sess_smtp_03_s1",
      event_type: "CAPABILITY_ADVERTISED",
      protocol: "SMTP",
      upgrade_status: "OFFERED_NOT_USED",
      observed_value: "250-STARTTLS",
      frame_numbers: [8],
      evidence_source: "TSHARK_REASSEMBLED_STREAM",
      completeness_status: "COMPLETE",
    },
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("1 & 3. Session header renders backend 5-tuple, protocol, stream ID, and findings", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("TCP Stream #1")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1:50123")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2:25")).toBeInTheDocument();
    expect(
      screen.getByText("Plaintext Transmission Despite Advertised Encryption Capability")
    ).toBeInTheDocument();
    expect(screen.getByText("EMAIL-STARTTLS-OFFERED-NOT-USED-001")).toBeInTheDocument();
  });

  it("11. Empty findings state renders cleanly when no findings generated", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue([]);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("No Security Findings Generated")).toBeInTheDocument();
  });

  it("13. Session API error state displays error card when session fetch fails", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockRejectedValue(
      new Error("Session stream not found.")
    );
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue([]);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue([]);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("Session stream not found.")).toBeInTheDocument();
  });

  it("Case A: Valid session + valid finding + valid frame auto-opens finding drawer and highlights frame", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1?finding=fnd_001&frame=8"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("TCP Stream #1")).toBeInTheDocument();
    expect(await screen.findByText("Forensic Assessment & Description")).toBeInTheDocument();
  });

  it("Case B: Valid session + valid finding + no frame opens finding drawer without artificial error", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1?finding=fnd_001"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("Forensic Assessment & Description")).toBeInTheDocument();
    expect(screen.queryByText(/unavailable in reassembled stream timeline/i)).not.toBeInTheDocument();
  });

  it("Case C: Valid session + valid frame + no finding highlights frame without opening finding drawer", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1?frame=8"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("TCP Stream #1")).toBeInTheDocument();
    expect(screen.queryByText("Forensic Assessment & Description")).not.toBeInTheDocument();
  });

  it("Case D: Valid session + nonexistent finding ID loads session normally without crash or misleading finding", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1?finding=nonexistent_fnd_999"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("TCP Stream #1")).toBeInTheDocument();
    expect(screen.queryByText("Forensic Assessment & Description")).not.toBeInTheDocument();
  });

  it("Case E: Valid session + nonexistent frame displays explicit frame unavailable warning", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1?frame=999"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("TCP Stream #1")).toBeInTheDocument();
    expect(
      await screen.findByText(/Evidence frame #999 is referenced by finding/i)
    ).toBeInTheDocument();
  });

  it("Case F: Finding ID belonging to a different session is not loaded or associated with this session", async () => {
    vi.spyOn(sessionsApi, "getSessionDetail").mockResolvedValue(mockSession);
    // Findings returned for current session do NOT contain fnd_other_session_999
    vi.spyOn(sessionsApi, "getSessionFindings").mockResolvedValue(mockFindings);
    vi.spyOn(sessionsApi, "getSessionSecurityEvents").mockResolvedValue(mockSecEvents);

    render(
      <MemoryRouter initialEntries={["/sessions/sess_smtp_03_s1?finding=fnd_other_session_999"]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByText("TCP Stream #1")).toBeInTheDocument();
    expect(screen.queryByText("Forensic Assessment & Description")).not.toBeInTheDocument();
  });
});

