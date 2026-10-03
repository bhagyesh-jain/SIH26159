import { apiGet } from "./client";
import { JobResponse } from "../types/api";

export async function getJobStatus(jobId: string): Promise<JobResponse> {
  return apiGet<JobResponse>(`/api/v1/jobs/${jobId}`);
}
