import React, { useEffect, useState, useCallback } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import { ArrowLeft, Activity, ArrowRight } from "lucide-react";
import { getSessionDetail, getSessionFindings, getSessionSecurityEvents } from "../api/sessions";
import {
  SessionDetailResponse,
  FindingResponse,
  SecurityEventResponse,
  SecurityEventQueryParams,
} from "../types/api";
import { formatAddress, formatProtocol } from "../utils/formatting";
import { LoadingState } from "../components/common/LoadingState";
import { ErrorState } from "../components/common/ErrorState";
import { SessionFindingsTable } from "../components/findings/SessionFindingsTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { EvidenceTimeline } from "../components/timeline/EvidenceTimeline";
import { SecurityEventsTable } from "../components/events/SecurityEventsTable";

export const SessionDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();

  const [session, setSession] = useState<SessionDetailResponse | null>(null);
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEventResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [highlightedFrame, setHighlightedFrame] = useState<number | null>(null);

  const [secEventsLoading, setSecEventsLoading] = useState(false);
  const [secEventsError, setSecEventsError] = useState<string | null>(null);

  const fetchSessionData = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);

    try {
      const [sessData, findingsData, secEvtsData] = await Promise.all([
        getSessionDetail(id),
        getSessionFindings(id),
        getSessionSecurityEvents(id),
      ]);
      setSession(sessData);
      setFindings(findingsData);
      setSecurityEvents(secEvtsData);

      // Deep linking support via search params (finding ID / frame number)
      const findingParam = searchParams.get("finding");
      const frameParam = searchParams.get("frame");

      if (frameParam && !isNaN(Number(frameParam))) {
        setHighlightedFrame(Number(frameParam));
      }

      if (findingParam && findingsData.length > 0) {
        const targetFinding = findingsData.find(
          (f) => f.id === findingParam || f.rule_id === findingParam
        );
        if (targetFinding) {
          setSelectedFinding(targetFinding);
          if (!frameParam && targetFinding.evidence_frame_numbers?.length > 0) {
            setHighlightedFrame(targetFinding.evidence_frame_numbers[0]);
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to load forensic session stream data.");
      }
    } finally {
      setLoading(false);
    }
  }, [id, searchParams]);

  useEffect(() => {
    fetchSessionData();
  }, [fetchSessionData]);

  const handleSecurityEventFilterChange = async (filters: SecurityEventQueryParams) => {
    if (!id) return;
    setSecEventsLoading(true);
    setSecEventsError(null);
    try {
      const filtered = await getSessionSecurityEvents(id, filters);
      setSecurityEvents(filtered);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setSecEventsError(err.message);
      } else {
        setSecEventsError("Failed to fetch filtered security events.");
      }
    } finally {
      setSecEventsLoading(false);
    }
  };

  const handleSelectFrame = (frameNumber: number) => {
    setHighlightedFrame(frameNumber);
  };

  if (loading) {
    return <LoadingState message="Loading forensic TCP session timeline & evidence..." />;
  }

  if (error || !session) {
    return (
      <div>
        <Link
          to="/investigations"
          className="inline-flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-slate-200 mb-4 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Investigations
        </Link>
        <ErrorState
          title="Session Stream Not Found"
          message={error || "The requested TCP session stream does not exist."}
          onRetry={fetchSessionData}
        />
      </div>
    );
  }

  const proto = formatProtocol(session.protocol);
  const shortId = session.id.length > 16 ? `${session.id.slice(0, 12)}...` : session.id;

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-3">
          <Link to="/investigations" className="hover:text-cyan-400 transition-colors">
            Investigations
          </Link>
          <span>/</span>
          <Link
            to={`/investigations/${session.capture_id}`}
            className="hover:text-cyan-400 transition-colors"
          >
            Case #{session.capture_id.slice(0, 8)}
          </Link>
          <span>/</span>
          <span className="text-slate-200 font-bold">Session Stream #{session.tcp_stream}</span>
        </div>

        {/* Session Explorer Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-5 gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                TCP Stream #{session.tcp_stream}
              </span>
              <span className="text-xs font-mono font-bold text-slate-200 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                {proto}
              </span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60 flex items-center gap-1">
                <Activity className="w-3 h-3" /> {session.completeness || "COMPLETE"}
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
              {formatAddress(session.src, session.src_port)} <ArrowRight className="inline w-5 h-5 text-slate-500 mx-1" /> {formatAddress(session.dst, session.dst_port)}
            </h1>
          </div>

          <div className="flex items-center gap-3 self-start sm:self-auto flex-wrap">
            <div className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-2 rounded border border-slate-800 flex items-center gap-2">
              <span className="text-slate-500">Capture:</span>
              <span className="text-slate-100 font-bold">{session.capture_filename || session.capture_id}</span>
              {session.capture_sha256 && (
                <>
                  <span className="text-slate-700">|</span>
                  <span className="text-slate-500">SHA-256:</span>
                  <code
                    className="text-cyan-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800 text-[11px]"
                    title={session.capture_sha256}
                  >
                    {session.capture_sha256.length > 16
                      ? `${session.capture_sha256.slice(0, 8)}...${session.capture_sha256.slice(-8)}`
                      : session.capture_sha256}
                  </code>
                </>
              )}
            </div>

            <div className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-2 rounded border border-slate-800">
              Session ID: <code className="text-slate-200 font-bold" title={session.id}>{shortId}</code>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION A: Session Overview Card */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs">
        <div>
          <span className="text-slate-500 uppercase block text-[10px]">Protocol State</span>
          <span className="text-sm font-bold text-cyan-400">{proto}</span>
        </div>
        <div>
          <span className="text-slate-500 uppercase block text-[10px]">Client End-Point</span>
          <span className="text-sm font-bold text-slate-200">{formatAddress(session.src, session.src_port)}</span>
        </div>
        <div>
          <span className="text-slate-500 uppercase block text-[10px]">Server End-Point</span>
          <span className="text-sm font-bold text-slate-200">{formatAddress(session.dst, session.dst_port)}</span>
        </div>
        <div>
          <span className="text-slate-500 uppercase block text-[10px]">Reassembled Events</span>
          <span className="text-sm font-bold text-slate-200">{session.events_count ?? session.events.length}</span>
        </div>
      </div>

      {/* SECTION B: Security Findings */}
      <SessionFindingsTable
        findings={findings}
        onSelectFinding={(f) => setSelectedFinding(f)}
        onSelectFrame={handleSelectFrame}
      />

      {/* SECTION C: Evidence Timeline */}
      <EvidenceTimeline
        events={session.events}
        highlightedFrameNumber={highlightedFrame}
        onSelectFrame={handleSelectFrame}
      />

      {/* SECTION D: Security Events Table */}
      <SecurityEventsTable
        events={securityEvents}
        loading={secEventsLoading}
        error={secEventsError}
        onFilterChange={handleSecurityEventFilterChange}
      />

      {/* Finding Detail Panel Modal / Drawer */}
      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onSelectFrame={(frameNumber) => {
          handleSelectFrame(frameNumber);
        }}
        showSessionLink={false}
      />
    </div>
  );
};
