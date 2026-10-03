import { renderHook, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { useJobPoller } from "../useJobPoller";
import * as jobsApi from "../../api/jobs";
import { JobResponse } from "../../types/api";

vi.mock("../../api/jobs");

describe("useJobPoller Custom Hook Tests", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("7. Job polling reaches COMPLETED and stops polling", async () => {
    const jobProcessing: JobResponse = {
      id: "job_100",
      capture_id: "cap_100",
      state: "PROCESSING",
    };
    const jobCompleted: JobResponse = {
      id: "job_100",
      capture_id: "cap_100",
      state: "COMPLETED",
    };

    vi.spyOn(jobsApi, "getJobStatus")
      .mockResolvedValueOnce(jobProcessing)
      .mockResolvedValueOnce(jobCompleted);

    const onCompleted = vi.fn();

    const { result } = renderHook(() =>
      useJobPoller("job_100", { onCompleted, intervalMs: 50 })
    );

    await waitFor(() => {
      expect(result.current.job?.state).toBe("COMPLETED");
    });

    expect(onCompleted).toHaveBeenCalled();
    expect(result.current.polling).toBe(false);
  });

  it("8. Job polling reaches FAILED and triggers failure callback", async () => {
    const jobFailed: JobResponse = {
      id: "job_200",
      capture_id: "cap_200",
      state: "FAILED",
      error_code: "TSHARK_PARSER_ERROR",
    };

    vi.spyOn(jobsApi, "getJobStatus").mockResolvedValue(jobFailed);

    const onFailed = vi.fn();

    const { result } = renderHook(() =>
      useJobPoller("job_200", { onFailed, intervalMs: 50 })
    );

    await waitFor(() => {
      expect(result.current.job?.state).toBe("FAILED");
    });

    expect(onFailed).toHaveBeenCalledWith("TSHARK_PARSER_ERROR");
    expect(result.current.polling).toBe(false);
  });

  it("9. Polling interval is cleaned up when unmounted", async () => {
    const jobProcessing: JobResponse = {
      id: "job_300",
      capture_id: "cap_300",
      state: "PROCESSING",
    };

    vi.spyOn(jobsApi, "getJobStatus").mockResolvedValue(jobProcessing);

    const { unmount } = renderHook(() =>
      useJobPoller("job_300", { intervalMs: 50 })
    );

    await waitFor(() => {
      expect(jobsApi.getJobStatus).toHaveBeenCalled();
    });

    const callsBeforeUnmount = vi.mocked(jobsApi.getJobStatus).mock.calls.length;
    unmount();

    // Wait past timer duration to confirm no further API calls
    await new Promise((r) => setTimeout(r, 150));
    expect(jobsApi.getJobStatus).toHaveBeenCalledTimes(callsBeforeUnmount);
  });
});
