import { apiGet, apiPost } from "./client";
import {
  InvestigationCreate,
  InvestigationResponse,
  InvestigationSummaryResponse,
  InvestigationReportResponse,
  InvestigationIntelligenceResponse,
} from "../types/api";

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

export async function getInvestigationReport(
  id: string
): Promise<InvestigationReportResponse> {
  return apiGet<InvestigationReportResponse>(`/api/v1/investigations/${id}/report`);
}

export async function getInvestigationIntelligence(
  id: string
): Promise<InvestigationIntelligenceResponse> {
  return apiGet<InvestigationIntelligenceResponse>(`/api/v1/investigations/${id}/intelligence`);
}

