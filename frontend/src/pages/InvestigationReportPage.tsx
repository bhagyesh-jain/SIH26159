import React, { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  Printer,
  ShieldCheck,
  Layers,
  AlertTriangle,
  FileText,
  Lock,
  HelpCircle,
  ChevronRight,
  HardDrive,
} from "lucide-react";
import { getInvestigationReport } from "../api/investigations";
import {
  InvestigationResponse,
  InvestigationSummaryResponse,
  FindingResponse,
  SecurityEventResponse,
  CaptureResponse,
  FindingSeverity,
  FindingConfidence,
} from "../types/api";
import { formatTimestamp, formatFrameNumbers, formatBytes } from "../utils/formatting";
import { LoadingState } from "../components/common/LoadingState";
import { ErrorState } from "../components/common/ErrorState";

export const InvestigationReportPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [summary, setSummary] = useState<InvestigationSummaryResponse | null>(null);
  const [captures, setCaptures] = useState<CaptureResponse[]>([]);
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEventResponse[]>([]);
  const [evidenceScope, setEvidenceScope] = useState<string>("COMPLETE");
  const [generatedAt, setGeneratedAt] = useState<string>(new Date().toISOString());

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReportData = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);

    try {
      const reportData = await getInvestigationReport(id);

      setInvestigation({
        id: reportData.investigation_id,
        title: reportData.title,
        status: reportData.status,
        created_at: reportData.created_at,
      });
      setSummary(reportData.summary);
      setCaptures(reportData.captures || []);
      setFindings(reportData.findings);
      setSecurityEvents(reportData.security_events);
      setEvidenceScope(reportData.evidence_scope);
      if (reportData.generated_at) {
        setGeneratedAt(reportData.generated_at);
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to assemble forensic investigation report.");
      }
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchReportData();
  }, [fetchReportData]);

  const handlePrint = () => {
    window.print();
  };

  if (loading) {
    return <LoadingState message="Assembling authoritative forensic investigation report..." />;
  }

  if (error || !investigation || !summary) {
    return (
      <div>
        <Link
          to={`/investigations/${id || ""}`}
          className="inline-flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-slate-200 mb-4 transition-colors no-print"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Investigation Case
        </Link>
        <ErrorState
          title="Report Assembly Failed"
          message={error || "Failed to fetch authoritative evidence for this investigation case."}
          onRetry={fetchReportData}
        />
      </div>
    );
  }

  const getEpistemicLabel = (ruleId: string, severity: FindingSeverity) => {
    if (ruleId.startsWith("TLS-SECURE-BASELINE")) {
      return {
        label: "OBSERVED BASELINE",
        style: "bg-emerald-950/80 text-emerald-300 border-emerald-800/80",
        desc: "Positive security baseline verified directly by wire evidence.",
      };
    }
    if (ruleId.startsWith("TLS-ALERT-CERT") || ruleId.startsWith("TLS-WEAK-STATIC-RSA")) {
      return {
        label: "OBSERVED EVIDENCE",
        style: "bg-amber-950/80 text-amber-300 border-amber-800/80",
        desc: "Security anomaly verified by explicit wire protocol alerts or negotiation fields.",
      };
    }
    if (severity === "CRITICAL" || severity === "HIGH") {
      return {
        label: "OBSERVED EVIDENCE",
        style: "bg-red-950/80 text-red-300 border-red-800/80",
        desc: "Plaintext commands or security violation directly captured on wire.",
      };
    }
    return {
      label: "INFERRED / PASSIVE LIMITATION",
      style: "bg-slate-800 text-slate-300 border-slate-700",
      desc: "Protocol status observed with passive inspection boundary limits.",
    };
  };

  const getSeverityBadgeStyle = (severity: FindingSeverity) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-950 text-red-400 border-red-800";
      case "HIGH":
        return "bg-amber-950 text-amber-400 border-amber-800";
      case "MEDIUM":
        return "bg-yellow-950 text-yellow-400 border-yellow-800";
      case "LOW":
        return "bg-blue-950 text-blue-400 border-blue-800";
      case "INFO":
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const getConfidenceBadgeStyle = (confidence: FindingConfidence) => {
    switch (confidence) {
      case "HIGH":
        return "bg-emerald-950 text-emerald-300 border-emerald-800";
      case "MEDIUM":
        return "bg-cyan-950 text-cyan-300 border-cyan-800";
      case "LOW":
      case "UNKNOWN":
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto print:max-w-none print:m-0 print:p-0">
      {/* Top Action Bar (Screen Only) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4 no-print">
        <div className="flex items-center gap-2">
          <Link
            to={`/investigations/${investigation.id}`}
            className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Case Overview
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handlePrint}
            className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono text-xs font-bold rounded shadow transition-colors cursor-pointer"
          >
            <Printer className="w-4 h-4" /> Print / Save PDF Report
          </button>
        </div>
      </div>

      {/* Report Container */}
      <div className="bg-slate-900 print:bg-white border print:border-none border-slate-800 rounded-lg p-6 sm:p-10 space-y-8 font-sans text-slate-200 print:text-black">
        {/* Section 1: Header & Metadata */}
        <div className="border-b border-slate-800 print:border-slate-300 pb-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2 font-mono text-xs">
                <span className="font-bold text-cyan-400 print:text-cyan-700 bg-cyan-950/60 print:bg-cyan-50 px-2 py-0.5 rounded border border-cyan-800/60 print:border-cyan-200">
                  SECUREMAILSCOPE
                </span>
                <span className="text-slate-400 print:text-slate-600">|</span>
                <span className="text-slate-400 print:text-slate-600">
                  FORENSIC INVESTIGATION REPORT
                </span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight font-mono text-slate-100 print:text-black">
                {investigation.title}
              </h1>
            </div>

            <div className="font-mono text-xs text-slate-400 print:text-slate-700 bg-slate-950 print:bg-slate-100 p-3 rounded border border-slate-800 print:border-slate-300 space-y-1 self-start sm:self-auto">
              <div>
                <span className="text-slate-500 print:text-slate-600">Case ID: </span>
                <code className="font-bold text-slate-200 print:text-black">{investigation.id}</code>
              </div>
              <div>
                <span className="text-slate-500 print:text-slate-600">Case Status: </span>
                <span className="font-bold text-emerald-400 print:text-emerald-700">
                  {investigation.status}
                </span>
              </div>
              <div>
                <span className="text-slate-500 print:text-slate-600">Opened: </span>
                <span>{formatTimestamp(investigation.created_at)}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-slate-600">Generated: </span>
                <span>{formatTimestamp(generatedAt)}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-slate-600">Evidence Scope: </span>
                <span
                  className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                    evidenceScope === "COMPLETE"
                      ? "text-emerald-400 print:text-emerald-700 bg-emerald-950/60 print:bg-emerald-50 border border-emerald-800/60 print:border-emerald-200"
                      : "text-amber-400 print:text-amber-700 bg-amber-950/60 print:bg-amber-50 border border-amber-800/60 print:border-amber-200"
                  }`}
                >
                  {evidenceScope}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 text-xs font-mono text-slate-400 print:text-slate-600 italic flex items-center justify-between gap-4 flex-wrap">
            <span>Generated from the current investigation evidence set. Passive network packet capture analysis.</span>
            <span className="font-bold text-slate-300 print:text-slate-700">
              Evidence scope: {evidenceScope}
            </span>
          </div>
        </div>

        {/* Section 2: Executive Summary & Aggregated Metrics */}
        <div className="space-y-4">
          <h2 className="text-sm font-mono font-bold uppercase text-slate-300 print:text-slate-800 tracking-wider flex items-center gap-2 border-b border-slate-800 print:border-slate-300 pb-2">
            <FileText className="w-4 h-4 text-cyan-400 print:text-cyan-700" /> Executive Security Summary
          </h2>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div className="bg-slate-950 print:bg-slate-50 p-4 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-500 print:text-slate-600 uppercase block text-[10px]">Total Analyzed Sessions</span>
              <span className="text-2xl font-bold text-slate-100 print:text-black">
                {summary.totals.sessions_count}
              </span>
              <span className="text-[11px] text-slate-400 print:text-slate-600 block mt-1">
                across {summary.totals.captures_count} capture file(s)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-4 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-500 print:text-slate-600 uppercase block text-[10px]">Actionable Security Findings</span>
              <span className="text-2xl font-bold text-red-400 print:text-red-700">
                {summary.totals.actionable_findings_count}
              </span>
              <span className="text-[11px] text-slate-400 print:text-slate-600 block mt-1">
                ({summary.totals.informational_findings_count} informational)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-4 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-500 print:text-slate-600 uppercase block text-[10px]">Affected Sessions</span>
              <span className="text-2xl font-bold text-amber-400 print:text-amber-700">
                {summary.totals.affected_sessions_count}
              </span>
              <span className="text-[11px] text-slate-400 print:text-slate-600 block mt-1">
                out of {summary.totals.sessions_count} total sessions
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-4 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-500 print:text-slate-600 uppercase block text-[10px]">Highest Risk Priority Score</span>
              <span className="text-2xl font-bold text-cyan-400 print:text-cyan-700">
                {summary.totals.highest_risk_score} <span className="text-xs font-normal text-slate-500 print:text-slate-600">/ 100</span>
              </span>
              <span className="text-[11px] text-slate-400 print:text-slate-600 block mt-1">
                Evidence-adjusted priority
              </span>
            </div>
          </div>

          {/* Breakdown Grids */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs pt-2">
            {/* Severity Distribution */}
            <div className="bg-slate-950 print:bg-slate-50 p-4 rounded border border-slate-800 print:border-slate-300 space-y-3">
              <span className="text-slate-400 print:text-slate-700 font-bold uppercase text-[11px] block">
                Active Finding Severity Distribution
              </span>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-red-400 print:text-red-700 font-bold">CRITICAL</span>
                  <span className="font-bold">{summary.severity_breakdown.critical}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-amber-400 print:text-amber-700 font-bold">HIGH</span>
                  <span className="font-bold">{summary.severity_breakdown.high}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-yellow-400 print:text-yellow-700 font-bold">MEDIUM</span>
                  <span className="font-bold">{summary.severity_breakdown.medium}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-blue-400 print:text-blue-700 font-bold">LOW</span>
                  <span className="font-bold">{summary.severity_breakdown.low}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 print:text-slate-600 font-bold">INFO</span>
                  <span className="font-bold">{summary.severity_breakdown.info}</span>
                </div>
              </div>
            </div>

            {/* Protocol Distribution */}
            <div className="bg-slate-950 print:bg-slate-50 p-4 rounded border border-slate-800 print:border-slate-300 space-y-3">
              <span className="text-slate-400 print:text-slate-700 font-bold uppercase text-[11px] block">
                Protocol Traffic Breakdown
              </span>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-cyan-400 print:text-cyan-700 font-bold">SMTP Sessions</span>
                  <span className="font-bold">{summary.protocol_breakdown.smtp_sessions}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-purple-400 print:text-purple-700 font-bold">IMAP Sessions</span>
                  <span className="font-bold">{summary.protocol_breakdown.imap_sessions}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-indigo-400 print:text-indigo-700 font-bold">POP3 Sessions</span>
                  <span className="font-bold">{summary.protocol_breakdown.pop3_sessions}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 print:text-slate-600 font-bold">UNKNOWN Sessions</span>
                  <span className="font-bold">{summary.protocol_breakdown.unknown_sessions}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Section 2.5: Source Captures & Evidence Provenance */}
        <div className="space-y-4">
          <h2 className="text-sm font-mono font-bold uppercase text-slate-300 print:text-slate-800 tracking-wider flex items-center gap-2 border-b border-slate-800 print:border-slate-300 pb-2">
            <HardDrive className="w-4 h-4 text-cyan-400 print:text-cyan-700" /> Source Captures & Evidence Provenance ({captures.length})
          </h2>

          {captures.length === 0 ? (
            <div className="p-4 bg-slate-950 print:bg-slate-50 border border-slate-800 print:border-slate-300 rounded font-mono text-xs text-slate-500">
              No source capture files recorded for this investigation.
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-800 print:border-slate-300 rounded-lg">
              <table className="w-full text-left font-mono text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-950 print:bg-slate-100 text-slate-400 print:text-slate-700 border-b border-slate-800 print:border-slate-300">
                    <th className="py-2.5 px-3 font-semibold">Capture ID</th>
                    <th className="py-2.5 px-3 font-semibold">Filename</th>
                    <th className="py-2.5 px-3 font-semibold">Format</th>
                    <th className="py-2.5 px-3 font-semibold">Size</th>
                    <th className="py-2.5 px-3 font-semibold">Content SHA-256</th>
                    <th className="py-2.5 px-3 font-semibold">Uploaded</th>
                    <th className="py-2.5 px-3 font-semibold">Status</th>
                    <th className="py-2.5 px-3 font-semibold text-right">Sessions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 print:divide-slate-200 text-slate-300 print:text-black">
                  {captures.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-800/30 print:hover:bg-transparent">
                      <td className="py-2 px-3 font-bold text-cyan-400 print:text-cyan-800">{c.id}</td>
                      <td className="py-2 px-3 font-bold text-slate-100 print:text-black">{c.filename}</td>
                      <td className="py-2 px-3">{c.format}</td>
                      <td className="py-2 px-3">{formatBytes(c.bytes)}</td>
                      <td className="py-2 px-3">
                        <code className="text-slate-300 print:text-black font-mono text-[11px] bg-slate-950 print:bg-slate-100 px-1.5 py-0.5 rounded border border-slate-800 print:border-slate-300 select-all" title={c.sha256}>
                          {c.sha256.length > 16 ? `${c.sha256.slice(0, 8)}...${c.sha256.slice(-8)}` : c.sha256}
                        </code>
                      </td>
                      <td className="py-2 px-3 text-[11px] text-slate-400 print:text-slate-600">{formatTimestamp(c.uploaded_at)}</td>
                      <td className="py-2 px-3">
                        <span className="font-bold text-emerald-400 print:text-emerald-800">
                          {c.status || "COMPLETED"}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right font-bold">{c.sessions_count ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Section 3: Security Posture Summary */}
        <div className="space-y-4">
          <h2 className="text-sm font-mono font-bold uppercase text-slate-300 print:text-slate-800 tracking-wider flex items-center gap-2 border-b border-slate-800 print:border-slate-300 pb-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 print:text-emerald-700" /> Security Posture Summary
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
            <div className="bg-slate-950 print:bg-slate-50 p-3.5 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-400 print:text-slate-700 block text-[11px] font-bold">Plaintext (No STARTTLS)</span>
              <span className="text-lg font-bold text-red-400 print:text-red-700">
                {summary.security_posture.plaintext_not_offered_sessions} session(s)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-3.5 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-400 print:text-slate-700 block text-[11px] font-bold">STARTTLS Offered Not Used</span>
              <span className="text-lg font-bold text-amber-400 print:text-amber-700">
                {summary.security_posture.starttls_offered_not_used_sessions} session(s)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-3.5 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-400 print:text-slate-700 block text-[11px] font-bold">Weak Static RSA Cipher</span>
              <span className="text-lg font-bold text-amber-400 print:text-amber-700">
                {summary.security_posture.weak_static_rsa_sessions} session(s)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-3.5 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-400 print:text-slate-700 block text-[11px] font-bold">Certificate Wire Alert</span>
              <span className="text-lg font-bold text-yellow-400 print:text-yellow-700">
                {summary.security_posture.certificate_alert_sessions} session(s)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-3.5 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-400 print:text-slate-700 block text-[11px] font-bold">TLS Handshake Failed</span>
              <span className="text-lg font-bold text-red-400 print:text-red-700">
                {summary.security_posture.handshake_failed_sessions} session(s)
              </span>
            </div>

            <div className="bg-slate-950 print:bg-slate-50 p-3.5 rounded border border-slate-800 print:border-slate-300">
              <span className="text-slate-400 print:text-slate-700 block text-[11px] font-bold">Secure TLS Baseline</span>
              <span className="text-lg font-bold text-emerald-400 print:text-emerald-700">
                {summary.security_posture.secure_baseline_sessions} session(s)
              </span>
            </div>
          </div>
        </div>

        {/* Section 4: Prioritized Security Findings */}
        <div className="space-y-6">
          <h2 className="text-sm font-mono font-bold uppercase text-slate-300 print:text-slate-800 tracking-wider flex items-center gap-2 border-b border-slate-800 print:border-slate-300 pb-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 print:text-amber-700" /> Prioritized Security Findings ({findings.length})
          </h2>

          {findings.length === 0 ? (
            <div className="p-8 bg-slate-950 print:bg-slate-50 border border-slate-800 print:border-slate-300 rounded-lg text-center font-mono text-xs text-slate-400 print:text-slate-600">
              No security findings identified in analyzed capture streams.
            </div>
          ) : (
            <div className="space-y-6">
              {findings.map((f, idx) => {
                const epistemic = getEpistemicLabel(f.rule_id, f.severity);

                return (
                  <div
                    key={f.id}
                    className="bg-slate-950 print:bg-white border border-slate-800 print:border-slate-300 rounded-lg p-5 font-mono space-y-4 shadow-xs"
                  >
                    {/* Finding Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 print:border-slate-200 pb-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap text-xs">
                          <span className="text-slate-500 font-bold">#{idx + 1}</span>
                          <span
                            className={`px-2 py-0.5 rounded font-bold border text-[11px] ${getSeverityBadgeStyle(
                              f.severity
                            )}`}
                          >
                            {f.severity}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded font-bold border text-[11px] ${getConfidenceBadgeStyle(
                              f.confidence
                            )}`}
                          >
                            {f.confidence} CONFIDENCE
                          </span>
                          <span className="text-cyan-400 print:text-cyan-700 font-bold bg-slate-900 print:bg-slate-100 px-2 py-0.5 rounded border border-slate-800 print:border-slate-300 text-[11px]">
                            Risk Score: {f.risk_score} / 100
                          </span>
                          <span className="text-slate-400 print:text-slate-600 bg-slate-900 print:bg-slate-100 px-2 py-0.5 rounded border border-slate-800 print:border-slate-300 text-[11px]">
                            Status: {f.status}
                          </span>
                        </div>
                        <h3 className="text-base font-bold text-slate-100 print:text-black tracking-tight">
                          {f.title}
                        </h3>
                      </div>

                      <div className="text-right text-xs self-start sm:self-auto shrink-0">
                        <span className="text-slate-500 print:text-slate-600 block text-[10px]">Rule ID</span>
                        <code className="text-slate-300 print:text-black font-bold">{f.rule_id}</code>
                      </div>
                    </div>

                    {/* Description */}
                    <div className="text-xs text-slate-300 print:text-slate-800 leading-relaxed font-sans">
                      {f.description}
                    </div>

                    {/* Epistemic Boundary Badge */}
                    <div className="p-3 rounded border font-mono text-xs space-y-1 bg-slate-900/60 print:bg-slate-50 print:border-slate-300">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${epistemic.style}`}
                        >
                          {epistemic.label}
                        </span>
                        <span className="text-slate-400 print:text-slate-600 text-[11px]">
                          Epistemic Provenance Category
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 print:text-slate-600 font-sans">
                        {epistemic.desc}
                      </p>
                    </div>

                    {/* Observed Wire Payload */}
                    {f.observed_value && (
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
                          Observed Wire Evidence Payload:
                        </span>
                        <div className="bg-slate-900 print:bg-slate-100 p-3 rounded border border-slate-800 print:border-slate-300 text-cyan-300 print:text-cyan-900 text-xs break-all font-mono">
                          {f.observed_value}
                        </div>
                      </div>
                    )}

                    {/* Traceability Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs bg-slate-900/40 print:bg-slate-50 p-3 rounded border border-slate-800/80 print:border-slate-300">
                      <div>
                        <span className="text-slate-500 uppercase block text-[10px]">Affected Session</span>
                        <Link
                          to={`/sessions/${f.session_id}?finding=${f.id}`}
                          className="font-bold text-cyan-400 print:text-cyan-700 hover:underline flex items-center gap-1 no-print"
                        >
                          {f.session_id.slice(0, 14)}... <ChevronRight className="w-3 h-3" />
                        </Link>
                        <span className="font-bold text-black hidden print:inline">
                          {f.session_id}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-500 uppercase block text-[10px]">Evidence Frames</span>
                        <span className="font-bold text-slate-200 print:text-black">
                          {formatFrameNumbers(f.evidence_frame_numbers)}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-500 uppercase block text-[10px]">Evidence Event IDs</span>
                        <span className="text-slate-300 print:text-black font-mono text-[11px]">
                          {f.evidence_event_ids && f.evidence_event_ids.length > 0
                            ? f.evidence_event_ids.join(", ")
                            : "INCOMPLETE"}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-500 uppercase block text-[10px]">First / Last Observed</span>
                        <span className="text-slate-300 print:text-black text-[11px]">
                          {f.first_seen ? formatTimestamp(f.first_seen) : "—"}
                        </span>
                      </div>
                    </div>

                    {/* Extra Details / Remediation */}
                    {f.details && Object.keys(f.details).length > 0 && (
                      <div className="text-xs space-y-1 border-t border-slate-800/60 print:border-slate-200 pt-3">
                        <span className="text-slate-500 uppercase text-[10px] block font-bold">
                          Forensic Context & Remediation Note
                        </span>
                        {typeof f.details.remediation === "string" && (
                          <p className="text-emerald-400 print:text-emerald-800 font-sans text-xs">
                            <strong>Remediation:</strong> {f.details.remediation}
                          </p>
                        )}
                        {f.details.credential_exposure_observed === true && (
                          <div className="text-red-400 print:text-red-700 font-mono text-xs flex items-center gap-1.5 mt-1">
                            <Lock className="w-3.5 h-3.5 text-red-400" />
                            <span>CRITICAL: Plaintext Credential Transmission Captured on Wire.</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Section 5: Forensic Evidence Appendix */}
        <div className="space-y-4">
          <h2 className="text-sm font-mono font-bold uppercase text-slate-300 print:text-slate-800 tracking-wider flex items-center gap-2 border-b border-slate-800 print:border-slate-300 pb-2">
            <Layers className="w-4 h-4 text-cyan-400 print:text-cyan-700" /> Forensic Evidence Appendix ({securityEvents.length} Events)
          </h2>

          {securityEvents.length === 0 ? (
            <div className="p-6 bg-slate-950 print:bg-slate-50 border border-slate-800 print:border-slate-300 rounded text-center font-mono text-xs text-slate-500">
              No security events recorded.
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-800 print:border-slate-300 rounded-lg">
              <table className="w-full text-left font-mono text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-950 print:bg-slate-100 text-slate-400 print:text-slate-700 border-b border-slate-800 print:border-slate-300">
                    <th className="py-2.5 px-3 font-semibold">Frame(s)</th>
                    <th className="py-2.5 px-3 font-semibold">Event Type</th>
                    <th className="py-2.5 px-3 font-semibold">Protocol</th>
                    <th className="py-2.5 px-3 font-semibold">Upgrade Status</th>
                    <th className="py-2.5 px-3 font-semibold">Source</th>
                    <th className="py-2.5 px-3 font-semibold">Completeness</th>
                    <th className="py-2.5 px-3 font-semibold">Observed Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 print:divide-slate-200 text-slate-300 print:text-black">
                  {securityEvents.slice(0, 50).map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-800/30 print:hover:bg-transparent">
                      <td className="py-2 px-3 font-bold text-cyan-400 print:text-cyan-800">
                        {formatFrameNumbers(evt.frame_numbers)}
                      </td>
                      <td className="py-2 px-3 font-bold">{evt.event_type}</td>
                      <td className="py-2 px-3">{evt.protocol}</td>
                      <td className="py-2 px-3 text-emerald-400 print:text-emerald-800 font-semibold">
                        {evt.upgrade_status || "—"}
                      </td>
                      <td className="py-2 px-3 text-[11px] text-slate-400 print:text-slate-600">
                        {evt.evidence_source || "TSHARK_REASSEMBLED_STREAM"}
                      </td>
                      <td className="py-2 px-3 text-[11px]">
                        {evt.completeness_status || "COMPLETE"}
                      </td>
                      <td className="py-2 px-3 max-w-xs truncate text-[11px] text-cyan-300 print:text-cyan-900 font-mono">
                        {evt.observed_value || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {securityEvents.length > 50 && (
                <div className="p-2 text-center text-[11px] font-mono text-slate-500 bg-slate-950 border-t border-slate-800">
                  Showing first 50 security events of {securityEvents.length} total.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Section 6: Methodology & Forensic Disclosures */}
        <div className="bg-slate-950 print:bg-slate-100 p-5 rounded-lg border border-slate-800 print:border-slate-300 font-mono text-xs space-y-3">
          <h3 className="font-bold text-slate-200 print:text-black uppercase text-[11px] tracking-wider flex items-center gap-1.5">
            <HelpCircle className="w-4 h-4 text-cyan-400 print:text-cyan-700" /> Assessment Methodology & Forensic Limitations
          </h3>
          <ul className="list-disc pl-5 space-y-1.5 text-slate-400 print:text-slate-700 font-sans text-[11px] leading-relaxed">
            <li>
              <strong>Passive Capture Analysis:</strong> Analysis is executed via passive TShark extraction and deterministic state machine TCP stream reassembly without active network probing or injection.
            </li>
            <li>
              <strong>Cryptographic Visibility Boundaries:</strong> TLS handshake analysis evaluates wire negotiation parameters (cipher suites, extensions, TLS versions, wire alerts). Inner post-handshake traffic and encrypted X.509 certificate chains under TLS 1.3 remain uninspectable without out-of-band TLS session key logs.
            </li>
            <li>
              <strong>Evidence Epistemics:</strong> Findings are categorized strictly by observable evidence. Absence of evidence or incomplete streams are preserved as UNCOMPLETE / UNKNOWN and are never assumed as proof of security or failure.
            </li>
            <li>
              <strong>Credential Protection:</strong> Captured authentication credentials in protocol streams are automatically masked (redacted) in findings and reports to prevent secondary credential leakage.
            </li>
          </ul>
        </div>

        {/* Report Footer */}
        <div className="border-t border-slate-800 print:border-slate-300 pt-4 flex flex-col sm:flex-row items-center justify-between text-[11px] font-mono text-slate-500">
          <div>SecureMailScope — Evidence-First Passive Forensic Platform</div>
          <div>Report Case ID: {investigation.id}</div>
        </div>
      </div>
    </div>
  );
};
