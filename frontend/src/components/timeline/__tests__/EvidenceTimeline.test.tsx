import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { EvidenceTimeline } from "../EvidenceTimeline";
import { EventResponse } from "../../../types/api";

describe("EvidenceTimeline Component Tests", () => {
  const mockEvents: EventResponse[] = [
    {
      id: "evt_001",
      packet_number: 8,
      event_type: "CAPABILITY_ADVERTISED",
      timestamp: "2026-10-04T02:00:00Z",
      observed_json: { raw: "250-STARTTLS" },
    },
    {
      id: "evt_002",
      packet_number: 9,
      event_type: "PLAINTEXT_COMMAND_AFTER_OFFER",
      timestamp: "2026-10-04T02:00:01Z",
      observed_json: { raw: "MAIL FROM:<sender@lab.local>" },
    },
  ];

  it("2. Session events render chronologically with frame numbers", () => {
    render(<EvidenceTimeline events={mockEvents} />);

    expect(screen.getByText("Frame #8")).toBeInTheDocument();
    expect(screen.getByText("CAPABILITY_ADVERTISED")).toBeInTheDocument();
    expect(screen.getByText("Frame #9")).toBeInTheDocument();
    expect(screen.getByText("PLAINTEXT_COMMAND_AFTER_OFFER")).toBeInTheDocument();
  });

  it("8. Highlighting frame updates CSS class and frame selection callback works", () => {
    const onSelectFrame = vi.fn();

    render(
      <EvidenceTimeline
        events={mockEvents}
        highlightedFrameNumber={9}
        onSelectFrame={onSelectFrame}
      />
    );

    const frame8 = screen.getByText("Frame #8").closest("div");
    fireEvent.click(frame8!);

    expect(onSelectFrame).toHaveBeenCalledWith(8);
  });

  it("12. Renders empty message when events list is empty", () => {
    render(<EvidenceTimeline events={[]} />);

    expect(
      screen.getByText("No packet events extracted for this session stream.")
    ).toBeInTheDocument();
  });
});
