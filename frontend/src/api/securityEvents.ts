import { apiGet } from "./client";
import { SecurityEventResponse, SecurityEventQueryParams } from "../types/api";

export async function getInvestigationSecurityEvents(
  investigationId: string,
  params?: SecurityEventQueryParams
): Promise<SecurityEventResponse[]> {
  return apiGet<SecurityEventResponse[]>(
    `/api/v1/investigations/${investigationId}/security-events`,
    params
  );
}

export async function getSessionSecurityEvents(
  sessionId: string,
  params?: SecurityEventQueryParams
): Promise<SecurityEventResponse[]> {
  return apiGet<SecurityEventResponse[]>(
    `/api/v1/sessions/${sessionId}/security-events`,
    params
  );
}
