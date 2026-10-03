import { apiGet } from "./client";
import { HealthResponse } from "../types/api";

export async function getHealthStatus(): Promise<HealthResponse> {
  return apiGet<HealthResponse>("/api/v1/health");
}
