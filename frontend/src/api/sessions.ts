import { apiGet } from "./client";
import {
  SessionResponse,
  SessionDetailResponse,
  SecurityEventResponse,
  SecurityEventQueryParams,
  FindingResponse,
  FindingQueryParams,
} from "../types/api";

export async function listInvestigationSessions(
  investigationId: string
): Promise<SessionResponse[]> {
  return apiGet<SessionResponse[]>(
    `/api/v1/investigations/${investigationId}/sessions`
  );
}

export async function getSessionDetail(
  sessionId: string
): Promise<SessionDetailResponse> {
  return apiGet<SessionDetailResponse>(`/api/v1/sessions/${sessionId}`);
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

export async function getSessionFindings(
  sessionId: string,
  params?: FindingQueryParams
): Promise<FindingResponse[]> {
  return apiGet<FindingResponse[]>(
    `/api/v1/sessions/${sessionId}/findings`,
    params
  );
}
