import React from "react";
import { Link } from "react-router-dom";
import {
  BrainCircuit,
  ShieldAlert,
  Layers,
  Activity,
  ArrowRight,
  ExternalLink,
  Eye,
  HelpCircle,
  Wrench,
  CheckCircle2,
} from "lucide-react";
import { InvestigationIntelligenceResponse, FindingSeverity, FindingConfidence } from "../../types/api";
import { getSeverityClass, getSeverityLabel, getConfidenceLabel, getRiskScoreClass } from "../../utils/risk";

interface SecurityIntelligencePanelProps {
  intelligence: InvestigationIntelligenceResponse | null;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
}

export const SecurityIntelligencePanel: React.FC<SecurityIntelligencePanelProps> = ({
  intelligence,
  loading = false,
  error = null,
  onRetry,
}) => {
  if (loading) {
    return (
      <div className="p-8 bg-slate-900/60 border border-slate-800 rounded-lg text-center font-mono text-xs text-slate-400">
        <BrainCircuit className="w-6 h-6 animate-pulse text-cyan-400 mx-auto mb-2" />
        Calculating deterministic security intelligence & correlation patterns...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-5 bg-red-950/50 border border-red-800/80 rounded-lg font-mono text-xs text-red-300 flex items-center justify-between">
        <div>
          <div className="font-bold text-sm mb-0.5">Intelligence Generation Failed</div>
          <div>{error}</div>
        </div>
        {onRetry && (
          <button
            onClick={onRetry}
            className="px-3 py-1.5 bg-red-900 hover:bg-red-800 text-red-100 rounded transition-colors shrink-0"
          >
            Retry
          </button>
        )}
      </div>
    );
  }

  if (!intelligence) return null;

  const { risk_summary, protocol_exposure, pattern_summary, insights } = intelligence;

  const getEvidenceStateBadge = (state: string) => {
    switch (state) {
      case "OBSERVED":
        return {
          label: "OBSERVED EVIDENCE",
          style: "bg-cyan-950/80 text-cyan-400 border-cyan-800",
          icon: Eye,
        };
      case "OBSERVED_BASELINE":
        return {
          label: "OBSERVED BASELINE",
          style: "bg-slate-800 text-slate-300 border-slate-700",
          icon: CheckCircle2,
        };
      case "INCOMPLETE":
      case "UNKNOWN":
      default:
        return {
          label: "INCOMPLETE / UNKNOWN",
          style: "bg-amber-950/80 text-amber-400 border-amber-800",
          icon: HelpCircle,
        };
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Panel Header */}
      <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <BrainCircuit className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100">
              Security Intelligence & Correlation Layer
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-sans">
            Deterministic pattern aggregation derived exclusively from persisted findings & session evidence.
          </p>
        </div>

        <div className="text-xs text-slate-500 bg-slate-900 px-3 py-1.5 rounded border border-slate-800 self-start sm:self-auto">
          Generated: <span className="text-slate-300">{new Date(intelligence.generated_at).toLocaleString()}</span>
        </div>
      </div>

      {/* SECTION 1: Intelligence Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-1">
          <span className="text-slate-500 uppercase block text-[10px]">Highest Risk Priority</span>
          <div className="flex items-baseline justify-between">
            <span className={`text-2xl font-bold ${getRiskScoreClass(risk_summary.highest_risk_score)}`}>
              {risk_summary.highest_risk_score} <span className="text-xs font-normal text-slate-500">/ 100</span>
            </span>
            {risk_summary.highest_risk_session_id && (
              <Link
                to={`/sessions/${risk_summary.highest_risk_session_id}${risk_summary.highest_risk_finding_id ? `?finding=${risk_summary.highest_risk_finding_id}` : ''}`}
                className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
                title="Inspect session stream"
              >
                Inspect <ArrowRight className="w-3 h-3" />
              </Link>
            )}
          </div>
          <span className="text-[11px] text-slate-400 block pt-1 border-t border-slate-800/60 truncate">
            {risk_summary.highest_risk_finding_id ? `Target Finding: ${risk_summary.highest_risk_finding_id}` : "No Active Security Findings"}
          </span>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-1">
          <span className="text-slate-500 uppercase block text-[10px]">Active Findings</span>
          <span className="text-2xl font-bold text-slate-100 block">
            {risk_summary.active_findings_count}
          </span>
          <span className="text-[11px] text-slate-400 block pt-1 border-t border-slate-800/60">
            across {risk_summary.affected_sessions_count} affected session(s)
          </span>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-1">
          <span className="text-slate-500 uppercase block text-[10px]">Repeated Rule Patterns</span>
          <span className="text-2xl font-bold text-amber-400 block">
            {pattern_summary.repeated_rules.length}
          </span>
          <span className="text-[11px] text-slate-400 block pt-1 border-t border-slate-800/60">
            {pattern_summary.affected_protocols.length > 0 ? `Protocols: ${pattern_summary.affected_protocols.join(", ")}` : "No repeated patterns"}
          </span>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-1">
          <span className="text-slate-500 uppercase block text-[10px]">Priority Insights</span>
          <span className="text-2xl font-bold text-cyan-400 block">
            {insights.length}
          </span>
          <span className="text-[11px] text-slate-400 block pt-1 border-t border-slate-800/60">
            Explainable correlation findings
          </span>
        </div>
      </div>

      {/* SECTION 2: Protocol Exposure Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
        <div className="p-4 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" /> Protocol Exposure & Threat Matrix
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-950/90 text-slate-400 border-b border-slate-800">
                <th className="py-2.5 px-4 font-semibold">Protocol</th>
                <th className="py-2.5 px-4 font-semibold">Sessions Total</th>
                <th className="py-2.5 px-4 font-semibold">Affected Sessions</th>
                <th className="py-2.5 px-4 font-semibold">Active Findings</th>
                <th className="py-2.5 px-4 font-semibold">Max Risk</th>
                <th className="py-2.5 px-4 font-semibold">Dominant Rule</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {protocol_exposure.map((p) => (
                <tr key={p.protocol} className="hover:bg-slate-800/30">
                  <td className="py-2.5 px-4 font-bold text-cyan-400">{p.protocol}</td>
                  <td className="py-2.5 px-4">{p.total_sessions}</td>
                  <td className="py-2.5 px-4 font-semibold text-amber-400">
                    {p.affected_sessions} / {p.total_sessions}
                  </td>
                  <td className="py-2.5 px-4">{p.active_findings_count}</td>
                  <td className="py-2.5 px-4">
                    <span className={`font-bold ${getRiskScoreClass(p.highest_risk_score)}`}>
                      {p.highest_risk_score} / 100
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-300">
                    {p.dominant_rule_id ? (
                      <code className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-[11px] text-cyan-300">
                        {p.dominant_rule_id}
                      </code>
                    ) : (
                      <span className="text-slate-500 italic">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* SECTION 3: Priority Intelligence Insights */}
      <div className="space-y-4 font-mono">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" /> Correlated Priority Insights ({insights.length})
          </h3>
        </div>

        {insights.length === 0 ? (
          <div className="p-8 bg-slate-900/40 border border-slate-800 rounded-lg text-center font-mono text-xs text-slate-500">
            No repeated correlation patterns detected across active investigation sessions.
          </div>
        ) : (
          <div className="space-y-4">
            {insights.map((insight) => {
              const severityClass = getSeverityClass(insight.severity as FindingSeverity);
              const severityLabel = getSeverityLabel(insight.severity as FindingSeverity);
              const confidenceLabel = getConfidenceLabel(insight.confidence as FindingConfidence);
              const evidenceStateBadge = getEvidenceStateBadge(insight.evidence_state);
              const StateIcon = evidenceStateBadge.icon;
              const firstSessionId = insight.supporting_session_ids?.[0];
              const firstFindingId = insight.supporting_finding_ids?.[0];

              return (
                <div
                  key={insight.id}
                  className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4 shadow-sm"
                >
                  {/* Insight Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap text-xs">
                        <span className={`px-2.5 py-0.5 rounded font-bold border text-[11px] ${severityClass}`}>
                          {severityLabel}
                        </span>
                        <span className="px-2 py-0.5 bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px]">
                          {confidenceLabel}
                        </span>
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold border ${evidenceStateBadge.style}`}>
                          <StateIcon className="w-3 h-3" />
                          {evidenceStateBadge.label}
                        </span>
                        <span className="text-cyan-400 font-bold bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                          Risk Priority: {insight.risk_score} / 100
                        </span>
                      </div>

                      <h4 className="text-base font-bold text-slate-100 tracking-tight font-sans">
                        {insight.title}
                      </h4>
                    </div>

                    <div className="text-right text-xs self-start sm:self-auto shrink-0">
                      <span className="text-slate-500 block text-[10px]">Insight Pattern ID</span>
                      <code className="text-cyan-400 font-bold">{insight.id}</code>
                    </div>
                  </div>

                  {/* Description */}
                  <div className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-950/40 p-3.5 rounded border border-slate-800/80">
                    {insight.description}
                  </div>

                  {/* Evidence Provenance Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs bg-slate-950/60 p-3.5 rounded border border-slate-800">
                    <div>
                      <span className="text-slate-500 uppercase block text-[10px]">Supporting Findings</span>
                      <span className="text-slate-200 font-bold">
                        {insight.supporting_finding_ids.length} Finding(s)
                      </span>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5" title={insight.supporting_finding_ids.join(", ")}>
                        {insight.supporting_finding_ids.join(", ")}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 uppercase block text-[10px]">Affected Sessions</span>
                      <span className="text-slate-200 font-bold">
                        {insight.supporting_session_ids.length} Session(s)
                      </span>
                      <div className="text-[11px] text-cyan-400 truncate mt-0.5" title={insight.supporting_session_ids.join(", ")}>
                        {insight.supporting_session_ids.join(", ")}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 uppercase block text-[10px]">Supporting Frame Numbers</span>
                      <span className="text-slate-200 font-bold">
                        {insight.supporting_frame_numbers.length > 0 ? `Frames: ${insight.supporting_frame_numbers.join(", ")}` : "No frames recorded"}
                      </span>
                    </div>
                  </div>

                  {/* Remediation Note if available */}
                  {insight.remediation && (
                    <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded text-xs font-sans text-emerald-300 flex items-start gap-2">
                      <Wrench className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="font-mono uppercase text-[10px] text-emerald-400 block">Recommended Analyst Action:</strong>
                        {insight.remediation}
                      </div>
                    </div>
                  )}

                  {/* Action Link: Jump to Session Stream */}
                  {firstSessionId && (
                    <div className="flex justify-end pt-2 border-t border-slate-800/60">
                      <Link
                        to={`/sessions/${firstSessionId}${firstFindingId ? `?finding=${firstFindingId}` : ''}`}
                        className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-xs font-mono transition-colors inline-flex items-center gap-1.5"
                      >
                        <Activity className="w-3.5 h-3.5" /> Inspect Supporting Session <ExternalLink className="w-3 h-3" />
                      </Link>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
