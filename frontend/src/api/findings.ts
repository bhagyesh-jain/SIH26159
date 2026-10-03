import { apiGet } from "./client";
import { FindingResponse, FindingQueryParams } from "../types/api";

export async function getInvestigationFindings(
  investigationId: string,
  params?: FindingQueryParams
): Promise<FindingResponse[]> {
  return apiGet<FindingResponse[]>(
    `/api/v1/investigations/${investigationId}/findings`,
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
