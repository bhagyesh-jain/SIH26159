import { apiPostFormData } from "./client";
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
