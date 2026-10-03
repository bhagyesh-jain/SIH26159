import { FindingSeverity, FindingConfidence } from "../types/api";

export function getSeverityLabel(severity: FindingSeverity | string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    case "LOW":
      return "LOW";
    case "INFO":
      return "INFO";
    default:
      return String(severity || "UNKNOWN").toUpperCase();
  }
}

export function getSeverityClass(severity: FindingSeverity | string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "bg-red-950/80 text-red-400 border-red-800/60 font-semibold";
    case "HIGH":
      return "bg-amber-950/80 text-amber-400 border-amber-800/60 font-semibold";
    case "MEDIUM":
      return "bg-yellow-950/80 text-yellow-400 border-yellow-800/60 font-medium";
    case "LOW":
      return "bg-blue-950/80 text-blue-400 border-blue-800/60 font-medium";
    case "INFO":
      return "bg-slate-800/80 text-slate-300 border-slate-700 font-medium";
    default:
      return "bg-slate-800/50 text-slate-400 border-slate-700";
  }
}

export function getConfidenceLabel(confidence: FindingConfidence | string): string {
  switch (confidence?.toUpperCase()) {
    case "HIGH":
      return "HIGH CONFIDENCE";
    case "MEDIUM":
      return "MEDIUM CONFIDENCE";
    case "LOW":
      return "LOW CONFIDENCE";
    default:
      return "UNKNOWN CONFIDENCE";
  }
}

export function getRiskScoreClass(score: number): string {
  if (score >= 90) return "text-red-400 font-mono font-bold";
  if (score >= 70) return "text-amber-400 font-mono font-bold";
  if (score >= 40) return "text-yellow-400 font-mono font-medium";
  if (score > 0) return "text-blue-400 font-mono font-medium";
  return "text-slate-400 font-mono font-normal";
}
