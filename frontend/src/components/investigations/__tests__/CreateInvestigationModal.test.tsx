import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CreateInvestigationModal } from "../CreateInvestigationModal";
import * as invApi from "../../../api/investigations";

vi.mock("../../../api/investigations");

describe("CreateInvestigationModal Component Tests", () => {
  const onClose = vi.fn();
  const onCreated = vi.fn();

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("3. Create investigation submission calls API on valid input", async () => {
    const mockCreated = {
      id: "inv_12345",
      title: "Test Case Title",
      created_at: "2026-10-04T04:00:00Z",
      status: "ACTIVE",
    };
    vi.spyOn(invApi, "createInvestigation").mockResolvedValue(mockCreated);

    render(
      <CreateInvestigationModal
        isOpen={true}
        onClose={onClose}
        onCreated={onCreated}
      />
    );

    const input = screen.getByPlaceholderText(/Incident 2026-SMTP/i);
    fireEvent.change(input, { target: { value: "Test Case Title" } });

    const submitBtn = screen.getByRole("button", { name: /Create Case/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(invApi.createInvestigation).toHaveBeenCalledWith({
        title: "Test Case Title",
      });
      expect(onCreated).toHaveBeenCalledWith(mockCreated);
      expect(onClose).toHaveBeenCalled();
    });
  });

  it("4. Create investigation displays API error failure message", async () => {
    vi.spyOn(invApi, "createInvestigation").mockRejectedValue(
      new Error("Database write error")
    );

    render(
      <CreateInvestigationModal
        isOpen={true}
        onClose={onClose}
        onCreated={onCreated}
      />
    );

    const input = screen.getByPlaceholderText(/Incident 2026-SMTP/i);
    fireEvent.change(input, { target: { value: "Failing Title" } });

    const submitBtn = screen.getByRole("button", { name: /Create Case/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText("Database write error")).toBeInTheDocument();
    expect(onCreated).not.toHaveBeenCalled();
  });
});
