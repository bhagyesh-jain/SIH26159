import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SecurityEventsTable } from "../SecurityEventsTable";
import { SecurityEventResponse } from "../../../types/api";

describe("SecurityEventsTable Component Tests", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const mockEvents: SecurityEventResponse[] = [
    {
      id: "sevt_001",
      session_id: "sess_001",
      event_type: "CAPABILITY_ADVERTISED",
      protocol: "SMTP",
      upgrade_status: "OFFERED_NOT_USED",
      observed_value: "250-STARTTLS",
      frame_numbers: [8],
      timestamp: "2026-10-04T02:00:00Z",
      evidence_source: "TSHARK_REASSEMBLED_STREAM",
      completeness_status: "COMPLETE",
      details: { what: "STARTTLS capability response" },
    },
  ];

  it("10. Security event filter inputs trigger onFilterChange with query parameters", () => {
    const onFilterChange = vi.fn();

    render(
      <SecurityEventsTable
        events={mockEvents}
        onFilterChange={onFilterChange}
      />
    );

    // Filter by Event Type
    const typeInput = screen.getByPlaceholderText("Filter Event Type...");
    fireEvent.change(typeInput, { target: { value: "CAPABILITY" } });
    act(() => {
      vi.advanceTimersByTime(350);
    });

    expect(onFilterChange).toHaveBeenCalledWith({
      event_type: "CAPABILITY",
      upgrade_status: undefined,
      protocol: undefined,
      limit: 100,
      offset: 0,
    });

    // Filter by Protocol
    const protoSelect = screen.getByLabelText("Filter Protocol");
    fireEvent.change(protoSelect, { target: { value: "SMTP" } });

    expect(onFilterChange).toHaveBeenCalledWith({
      event_type: "CAPABILITY",
      upgrade_status: undefined,
      protocol: "SMTP",
      limit: 100,
      offset: 0,
    });

    // Clear Event Type filter
    fireEvent.change(typeInput, { target: { value: "" } });
    act(() => {
      vi.advanceTimersByTime(350);
    });

    expect(onFilterChange).toHaveBeenCalledWith({
      event_type: undefined,
      upgrade_status: undefined,
      protocol: "SMTP",
      limit: 100,
      offset: 0,
    });
  });

  it("Opening event detail modal exposes structured details", async () => {
    vi.useRealTimers();
    render(<SecurityEventsTable events={mockEvents} />);

    const viewBtn = screen.getByRole("button", { name: /View/i });
    fireEvent.click(viewBtn);

    expect(await screen.findByText("Security Event: CAPABILITY_ADVERTISED")).toBeInTheDocument();
    expect(screen.getAllByText("OFFERED_NOT_USED").length).toBeGreaterThan(0);
  });

  it("Displays error banner when API error occurs", () => {
    render(
      <SecurityEventsTable
        events={[]}
        error="Network error fetching backend query"
      />
    );

    expect(screen.getByText(/Failed to query security events: Network error fetching backend query/i)).toBeInTheDocument();
  });
});
