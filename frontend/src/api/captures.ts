import { apiPostFormData, apiGet } from "./client";
import { CaptureResponse } from "../types/api";

export async function uploadCapture(
  investigationId: string,
  file: File
): Promise<CaptureResponse> {
  const formData = new FormData();
  formData.append("file", file);
  return apiPostFormData<CaptureResponse>(
    `/api/v1/investigations/${investigationId}/captures`,
    formData
  );
}

export async function listInvestigationCaptures(
  investigationId: string
): Promise<CaptureResponse[]> {
  return apiGet<CaptureResponse[]>(
    `/api/v1/investigations/${investigationId}/captures`
  );
}

export async function getCapture(
  captureId: string
): Promise<CaptureResponse> {
  return apiGet<CaptureResponse>(`/api/v1/captures/${captureId}`);
}

