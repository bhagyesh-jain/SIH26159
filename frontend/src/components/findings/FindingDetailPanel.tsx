import React from "react";
import { X, ShieldAlert, Info, Eye, HelpCircle, ArrowUpRight } from "lucide-react";
import { FindingResponse } from "../../types/api";
import { formatTimestamp } from "../../utils/formatting";
import {
  getSeverityLabel,
  getSeverityClass,
  getConfidenceLabel,
  getRiskScoreClass,
} from "../../utils/risk";

interface FindingDetailPanelProps {
  finding: FindingResponse | null;
  onClose: () => void;
  onSelectFrame?: (frameNumber: number) => void;
  onSelectEventId?: (eventId: string) => void;
}

export const FindingDetailPanel: React.FC<FindingDetailPanelProps> = ({
  finding,
  onClose,
  onSelectFrame,
  onSelectEventId,
}) => {
  if (!finding) return null;

  const severityClass = getSeverityClass(finding.severity);
  const severityLabel = getSeverityLabel(finding.severity);
  const confidenceLabel = getConfidenceLabel(finding.confidence);
  const riskClass = getRiskScoreClass(finding.risk_score);

  // Determine Epistemic Classifier for the finding
  let epistemicBadge = {
    label: "OBSERVED EVIDENCE",
    icon: Eye,
    color: "bg-cyan-950/80 text-cyan-400 border-cyan-800",
  };
  if (finding.severity === "INFO") {
    epistemicBadge = {
      label: "OBSERVED BASELINE",
      icon: Info,
      color: "bg-slate-800 text-slate-300 border-slate-700",
    };
  } else if (finding.confidence === "MEDIUM" || finding.confidence === "LOW") {
    epistemicBadge = {
      label: "INFERRED / PASSIVE LIMITATION",
      icon: HelpCircle,
      color: "bg-amber-950/80 text-amber-400 border-amber-800",
    };
  }

  const EpistemicIcon = epistemicBadge.icon;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-xs">
      <div className="bg-slate-900 border-l border-slate-800 w-full max-w-2xl h-full overflow-y-auto p-6 shadow-2xl flex flex-col justify-between font-sans">
        <div className="space-y-6">
          {/* Panel Header */}
          <div className="flex items-start justify-between border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                <span
                  className={`inline-block px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${severityClass}`}
                >
                  {severityLabel}
                </span>
                <span className="inline-block px-2 py-0.5 bg-slate-800 text-slate-300 border border-slate-700 rounded text-xs font-mono">
                  {confidenceLabel}
                </span>
                <span
                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${epistemicBadge.color}`}
                >
                  <EpistemicIcon className="w-3.5 h-3.5" />
                  {epistemicBadge.label}
                </span>
              </div>
              <h2 className="text-xl font-bold font-mono text-slate-100 mt-2">
                {finding.title}
              </h2>
              <div className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
                <span>Rule: <code className="text-cyan-400 font-bold">{finding.rule_id}</code></span>
                <span>•</span>
                <span>ID: <code className="text-slate-300">{finding.id}</code></span>
              </div>
            </div>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 p-1.5 rounded hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Risk Score & Posture Metric Card */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/60 p-4 border border-slate-800 rounded-lg text-xs font-mono">
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Risk Priority Score</span>
              <span className={`text-xl font-bold ${riskClass}`}>
                {finding.risk_score} / 100
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Protocol</span>
              <span className="text-sm font-bold text-slate-200 uppercase">
                {finding.protocol}
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Status</span>
              <span className="text-sm font-bold text-emerald-400">
                {finding.status}
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Time Observed</span>
              <span className="text-[11px] text-slate-300">
                {formatTimestamp(finding.first_seen || finding.last_seen)}
              </span>
            </div>
          </div>

          {/* Description */}
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-bold uppercase text-slate-400 tracking-wider">
              Forensic Assessment & Description
            </h3>
            <div className="p-4 bg-slate-950/40 border border-slate-800/80 rounded-lg text-sm text-slate-300 leading-relaxed font-sans">
              {finding.description}
            </div>
          </div>

          {/* Observed Wire Payload / Value */}
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-bold uppercase text-slate-400 tracking-wider">
              Observed Wire Payload
            </h3>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 break-all">
              {finding.observed_value || "—"}
            </div>
          </div>

          {/* Evidence Frame Numbers & Event IDs Linking */}
          <div className="space-y-3 p-4 bg-slate-950/60 border border-slate-800 rounded-lg font-mono text-xs">
            <h3 className="font-bold text-slate-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-cyan-400" /> Evidence References & Frames
            </h3>

            {/* Frame Numbers */}
            <div>
              <span className="text-slate-400 block text-[11px] mb-1.5">
                Supporting Frame Numbers (Click to highlight in timeline):
              </span>
              {finding.evidence_frame_numbers && finding.evidence_frame_numbers.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {finding.evidence_frame_numbers.map((frame) => (
                    <button
                      key={frame}
                      onClick={() => onSelectFrame && onSelectFrame(frame)}
                      className="px-2.5 py-1 bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/80 rounded text-xs font-bold transition-all flex items-center gap-1 group"
                    >
                      Frame #{frame}
                      <ArrowUpRight className="w-3 h-3 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                    </button>
                  ))}
                </div>
              ) : (
                <span className="text-slate-500 italic">No frame numbers linked</span>
              )}
            </div>

            {/* Supporting Event IDs */}
            <div className="pt-2 border-t border-slate-800/80">
              <span className="text-slate-400 block text-[11px] mb-1.5">
                Supporting Security Event IDs:
              </span>
              {finding.evidence_event_ids && finding.evidence_event_ids.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {finding.evidence_event_ids.map((eventId) => (
                    <button
                      key={eventId}
                      onClick={() => onSelectEventId && onSelectEventId(eventId)}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[11px] font-mono transition-colors"
                    >
                      {eventId}
                    </button>
                  ))}
                </div>
              ) : (
                <span className="text-slate-500 italic">No event IDs linked</span>
              )}
            </div>
          </div>

          {/* Structured Details JSON View */}
          {finding.details && Object.keys(finding.details).length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold uppercase text-slate-400 tracking-wider">
                Structured Finding Context & Remediation
              </h3>
              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-300 overflow-x-auto">
                {JSON.stringify(finding.details, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Panel Footer */}
        <div className="pt-4 border-t border-slate-800 flex justify-end mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded transition-colors"
          >
            Close Detail Panel
          </button>
        </div>
      </div>
    </div>
  );
};
