import { useState, useEffect, useRef } from "react";
import { getJobStatus } from "../api/jobs";
import { JobResponse } from "../types/api";

interface UseJobPollerOptions {
  onCompleted?: () => void;
  onFailed?: (errorCode: string | null) => void;
  intervalMs?: number;
}

export function useJobPoller(
  jobId: string | null,
  options: UseJobPollerOptions = {}
) {
  const [job, setJob] = useState<JobResponse | null>(null);
  const [polling, setPolling] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const { onCompleted, onFailed, intervalMs = 1000 } = options;
  const onCompletedRef = useRef(onCompleted);
  const onFailedRef = useRef(onFailed);

  useEffect(() => {
    onCompletedRef.current = onCompleted;
    onFailedRef.current = onFailed;
  }, [onCompleted, onFailed]);

  useEffect(() => {
    if (!jobId) {
      setJob(null);
      setPolling(false);
      setError(null);
      return;
    }

    let isMounted = true;
    setPolling(true);
    setError(null);

    const pollJob = async () => {
      try {
        const res = await getJobStatus(jobId);
        if (!isMounted) return;

        setJob(res);

        if (res.state === "COMPLETED") {
          setPolling(false);
          if (onCompletedRef.current) {
            onCompletedRef.current();
          }
        } else if (res.state === "FAILED") {
          setPolling(false);
          if (onFailedRef.current) {
            onFailedRef.current(res.error_code || "Analysis job failed");
          }
        }
      } catch (err: unknown) {
        if (!isMounted) return;
        setPolling(false);
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError("Failed to fetch job status.");
        }
      }
    };

    // Immediate initial poll
    pollJob();

    // Setup interval loop
    const timer = setInterval(() => {
      if (isMounted) {
        pollJob();
      }
    }, intervalMs);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [jobId, intervalMs]);

  return { job, polling, error };
}
