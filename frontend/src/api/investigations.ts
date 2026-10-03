import { apiGet, apiPost } from "./client";
import { InvestigationCreate, InvestigationResponse, InvestigationSummaryResponse } from "../types/api";

export async function listInvestigations(): Promise<InvestigationResponse[]> {
  return apiGet<InvestigationResponse[]>("/api/v1/investigations");
}

export async function createInvestigation(
  payload: InvestigationCreate
): Promise<InvestigationResponse> {
  return apiPost<InvestigationResponse>("/api/v1/investigations", payload);
}

export async function getInvestigation(
  id: string
): Promise<InvestigationResponse> {
  return apiGet<InvestigationResponse>(`/api/v1/investigations/${id}`);
}

export async function getInvestigationSummary(
  id: string
): Promise<InvestigationSummaryResponse> {
  return apiGet<InvestigationSummaryResponse>(`/api/v1/investigations/${id}/summary`);
}
