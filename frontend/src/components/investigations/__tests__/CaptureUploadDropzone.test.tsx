import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CaptureUploadDropzone } from "../CaptureUploadDropzone";
import * as capturesApi from "../../../api/captures";

vi.mock("../../../api/captures");

describe("CaptureUploadDropzone Component Tests", () => {
  const onUploadSuccess = vi.fn();

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("5. File extension validation rejects non-pcap files with clear message", async () => {
    render(
      <CaptureUploadDropzone
        investigationId="inv_test"
        onUploadSuccess={onUploadSuccess}
      />
    );

    const dropzone = screen.getByText(/Drag & drop a/i);
    const invalidFile = new File(["dummy content"], "malicious.exe", {
      type: "application/x-msdownload",
    });

    fireEvent.drop(dropzone, {
      dataTransfer: {
        files: [invalidFile],
      },
    });

    expect(
      await screen.findByText(
        /Unsupported file format 'malicious.exe'. Only .pcap and .pcapng files are supported./i
      )
    ).toBeInTheDocument();
  });

  it("6. Successful PCAP upload submits file and invokes onUploadSuccess", async () => {
    const mockCap = {
      id: "cap_123",
      investigation_id: "inv_test",
      filename: "test.pcap",
      sha256: "a1b2c3d4e5f67890",
      bytes: 2048,
      format: "pcap",
      uploaded_at: "2026-10-04T04:00:00Z",
      job_id: "job_999",
    };

    vi.spyOn(capturesApi, "uploadCapture").mockResolvedValue(mockCap);

    render(
      <CaptureUploadDropzone
        investigationId="inv_test"
        onUploadSuccess={onUploadSuccess}
      />
    );

    const validFile = new File(["dummy pcap data"], "test.pcap", {
      type: "application/vnd.tcpdump.pcap",
    });

    const dropzone = screen.getByText(/Drag & drop a/i);
    fireEvent.drop(dropzone, {
      dataTransfer: {
        files: [validFile],
      },
    });

    expect(await screen.findByText("test.pcap")).toBeInTheDocument();

    const uploadBtn = screen.getByRole("button", { name: /Start Stream Analysis/i });
    fireEvent.click(uploadBtn);

    await waitFor(() => {
      expect(capturesApi.uploadCapture).toHaveBeenCalledWith("inv_test", validFile);
      expect(onUploadSuccess).toHaveBeenCalledWith(mockCap);
    });
  });
});
