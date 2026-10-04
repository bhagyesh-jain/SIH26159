import React, { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, ShieldCheck, Loader2, AlertTriangle, CheckCircle2, FileText, HardDrive, LayoutDashboard, Layers } from "lucide-react";
import { getInvestigation, getInvestigationSummary } from "../api/investigations";
import { listInvestigationSessions } from "../api/sessions";
import { listInvestigationCaptures } from "../api/captures";
import { getInvestigationFindings } from "../api/findings";
import {
  InvestigationResponse,
  SessionResponse,
  CaptureResponse,
  InvestigationSummaryResponse,
  FindingResponse,
} from "../types/api";
import { formatTimestamp } from "../utils/formatting";
import { useJobPoller } from "../hooks/useJobPoller";
import { LoadingState } from "../components/common/LoadingState";
import { ErrorState } from "../components/common/ErrorState";
import { CaptureUploadDropzone } from "../components/investigations/CaptureUploadDropzone";
import { CaptureTable } from "../components/captures/CaptureTable";
import { CaptureDetailModal } from "../components/captures/CaptureDetailModal";
import { SessionTable } from "../components/sessions/SessionTable";
import { OverviewMetricCards } from "../components/overview/OverviewMetricCards";
import { SecurityPostureGrid } from "../components/overview/SecurityPostureGrid";
import { SeverityDistributionBar } from "../components/overview/SeverityDistributionBar";
import { EvidenceQualityPanel } from "../components/overview/EvidenceQualityPanel";
import { TopFindingsCard } from "../components/overview/TopFindingsCard";

type WorkspaceTab = "overview" | "captures" | "sessions";

export const InvestigationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const [investigation, setInvestigation] = useState<InvestigationResponse | null>(null);
  const [captures, setCaptures] = useState<CaptureResponse[]>([]);
  const [sessions, setSessions] = useState<SessionResponse[]>([]);
  const [summary, setSummary] = useState<InvestigationSummaryResponse | null>(null);
  const [topFindings, setTopFindings] = useState<FindingResponse[]>([]);

  const [activeTab, setActiveTab] = useState<WorkspaceTab>("overview");
  const [selectedCapture, setSelectedCapture] = useState<CaptureResponse | null>(null);

  const [loadingInv, setLoadingInv] = useState(true);
  const [loadingCaptures, setLoadingCaptures] = useState(true);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [activeJobId, setActiveJobId] = useState<string | null>(null);

  const fetchInvestigationData = useCallback(async () => {
    if (!id) return;
    setLoadingInv(true);
    setError(null);

    try {
      const invData = await getInvestigation(id);
      setInvestigation(invData);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to load investigation details.");
      }
    } finally {
      setLoadingInv(false);
    }
  }, [id]);

  const fetchCaptures = useCallback(async () => {
    if (!id) return;
    setLoadingCaptures(true);
    try {
      const capData = await listInvestigationCaptures(id);
      setCaptures(capData);
    } catch {
      // Keep existing captures on refresh fail
    } finally {
      setLoadingCaptures(false);
    }
  }, [id]);

  const fetchSummaryData = useCallback(async () => {
    if (!id) return;
    setLoadingSummary(true);
    setSummaryError(null);

    try {
      const [sumData, findingsData] = await Promise.all([
        getInvestigationSummary(id),
        getInvestigationFindings(id, { status: "ACTIVE", limit: 5 }),
      ]);
      setSummary(sumData);
      setTopFindings(findingsData);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setSummaryError(err.message);
      } else {
        setSummaryError("Failed to fetch investigation summary metrics.");
      }
    } finally {
      setLoadingSummary(false);
    }
  }, [id]);

  const fetchSessions = useCallback(async () => {
    if (!id) return;
    setLoadingSessions(true);

    try {
      const sessionData = await listInvestigationSessions(id);
      setSessions(sessionData);
    } catch {
      // Keep existing sessions if refresh fails
    } finally {
      setLoadingSessions(false);
    }
  }, [id]);

  useEffect(() => {
    fetchInvestigationData();
    fetchCaptures();
    fetchSummaryData();
    fetchSessions();
  }, [fetchInvestigationData, fetchCaptures, fetchSummaryData, fetchSessions]);

  // Hook up Job Poller for background TShark stream analysis
  const { job, polling, error: jobError } = useJobPoller(activeJobId, {
    onCompleted: () => {
      fetchCaptures();
      fetchSummaryData();
      fetchSessions();
    },
  });

  const handleUploadSuccess = (capture: CaptureResponse) => {
    if (capture.job_id) {
      setActiveJobId(capture.job_id);
    }
    fetchCaptures();
    fetchSummaryData();
    fetchSessions();
  };

  if (loadingInv) {
    return <LoadingState message="Loading investigation case workspace..." />;
  }

  if (error || !investigation) {
    return (
      <div>
        <Link
          to="/investigations"
          className="inline-flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-slate-200 mb-4 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Investigations
        </Link>
        <ErrorState
          title="Case Not Found"
          message={error || "The requested investigation case does not exist."}
          onRetry={fetchInvestigationData}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 font-sans">
      {/* Breadcrumb & Navigation */}
      <div>
        <Link
          to="/investigations"
          className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors mb-3"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to All Investigations
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-5 gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                {investigation.id}
              </span>
              <span className="inline-flex items-center gap-1 text-xs font-mono font-semibold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                <ShieldCheck className="w-3.5 h-3.5" /> {investigation.status}
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
              {investigation.title}
            </h1>
          </div>

          <div className="flex items-center gap-3 self-start sm:self-auto">
            <Link
              to={`/investigations/${investigation.id}/report`}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono text-xs font-bold rounded shadow transition-colors"
            >
              <FileText className="w-4 h-4" /> Generate Report
            </Link>

            <div className="text-xs font-mono text-slate-400 flex items-center gap-2 bg-slate-900 px-3 py-2 rounded border border-slate-800">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>Opened: {formatTimestamp(investigation.created_at)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Job Polling Status Banner */}
      {job && (
        <div
          className={`p-4 border rounded-lg font-mono text-xs flex items-center justify-between gap-4 ${
            job.state === "PROCESSING" || job.state === "QUEUED"
              ? "bg-cyan-950/40 border-cyan-800/80 text-cyan-200"
              : job.state === "COMPLETED"
              ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-200"
              : "bg-red-950/40 border-red-800/80 text-red-200"
          }`}
        >
          <div className="flex items-center gap-3">
            {job.state === "PROCESSING" || job.state === "QUEUED" ? (
              <Loader2 className="w-5 h-5 animate-spin text-cyan-400 shrink-0" />
            ) : job.state === "COMPLETED" ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            )}

            <div>
              <div className="font-semibold text-sm">
                Job State: {job.state === "QUEUED" ? "Waiting for analysis" : job.state === "PROCESSING" ? "Analyzing capture" : job.state === "COMPLETED" ? "Analysis complete" : "Analysis failed"}
              </div>
              <div className="text-[11px] opacity-80 mt-0.5">
                Job ID: {job.id} | Parser: {job.parser_version || "tshark-1.0"}
                {job.error_code && ` | Error: ${job.error_code}`}
              </div>
            </div>
          </div>

          {polling && (
            <span className="text-[11px] bg-slate-900/80 text-cyan-300 px-2.5 py-1 rounded border border-cyan-800/60 shrink-0">
              Live Polling (1s)
            </span>
          )}
        </div>
      )}

      {jobError && (
        <div className="p-3 bg-red-950/50 border border-red-800 rounded text-xs font-mono text-red-300">
          Job Status Poller Warning: {jobError}
        </div>
      )}

      {/* PCAP Upload Section */}
      <CaptureUploadDropzone
        investigationId={investigation.id}
        onUploadSuccess={handleUploadSuccess}
        disabled={polling}
      />

      {/* Investigation Workspace Navigation Tabs */}
      <div className="border-b border-slate-800 flex items-center gap-2">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-4 py-2.5 text-xs font-mono font-bold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "overview"
              ? "border-cyan-400 text-cyan-400 bg-slate-900/60"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <LayoutDashboard className="w-4 h-4" /> SOC Overview
        </button>
        <button
          onClick={() => setActiveTab("captures")}
          className={`px-4 py-2.5 text-xs font-mono font-bold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "captures"
              ? "border-cyan-400 text-cyan-400 bg-slate-900/60"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <HardDrive className="w-4 h-4" /> Source Captures ({captures.length})
        </button>
        <button
          onClick={() => setActiveTab("sessions")}
          className={`px-4 py-2.5 text-xs font-mono font-bold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "sessions"
              ? "border-cyan-400 text-cyan-400 bg-slate-900/60"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Layers className="w-4 h-4" /> Sessions ({sessions.length})
        </button>
      </div>

      {/* Workspace Tab Contents */}
      {activeTab === "overview" && (
        <>
          {summaryError && (
            <div className="p-4 bg-red-950/50 border border-red-800/80 text-red-300 rounded-lg font-mono text-xs flex items-center justify-between">
              <span>Failed to load investigation summary: {summaryError}</span>
              <button
                onClick={fetchSummaryData}
                className="px-2.5 py-1 bg-red-900 hover:bg-red-800 text-red-100 rounded text-xs transition-colors"
              >
                Retry
              </button>
            </div>
          )}

          {loadingSummary ? (
            <LoadingState message="Calculating authoritative investigation security posture metrics..." />
          ) : summary ? (
            <div className="space-y-6">
              <OverviewMetricCards
                totals={summary.totals}
                protocolBreakdown={summary.protocol_breakdown}
              />

              <SeverityDistributionBar breakdown={summary.severity_breakdown} />

              <SecurityPostureGrid posture={summary.security_posture} />

              <EvidenceQualityPanel evidenceQuality={summary.evidence_quality} />

              <TopFindingsCard findings={topFindings} />
            </div>
          ) : null}
        </>
      )}

      {activeTab === "captures" && (
        <div className="space-y-6">
          <CaptureTable
            captures={captures}
            loading={loadingCaptures}
            onSelectCapture={(c) => setSelectedCapture(c)}
          />
        </div>
      )}

      {activeTab === "sessions" && (
        <div className="space-y-6">
          <SessionTable sessions={sessions} loading={loadingSessions} />
        </div>
      )}

      {/* Capture Detail Modal */}
      <CaptureDetailModal
        capture={selectedCapture}
        onClose={() => setSelectedCapture(null)}
        onNavigateToSessions={() => {
          setActiveTab("sessions");
        }}
      />
    </div>
  );
};

