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
  Cpu,
  AlertTriangle,
  Sparkles,
} from "lucide-react";
import {
  InvestigationIntelligenceResponse,
  InvestigationAnomaliesResponse,
  FindingSeverity,
} from "../../types/api";
import { getSeverityClass, getSeverityLabel, getRiskScoreClass } from "../../utils/risk";

interface SecurityIntelligencePanelProps {
  intelligence: InvestigationIntelligenceResponse | null;
  anomalies?: InvestigationAnomaliesResponse | null;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
}

export const SecurityIntelligencePanel: React.FC<SecurityIntelligencePanelProps> = ({
  intelligence,
  anomalies = null,
  loading = false,
  error = null,
  onRetry,
}) => {
  if (loading) {
    return (
      <div className="p-8 bg-slate-900/60 border border-slate-800 rounded-lg text-center font-mono text-xs text-slate-400">
        <BrainCircuit className="w-6 h-6 animate-pulse text-cyan-400 mx-auto mb-2" />
        Calculating deterministic security intelligence & ML anomaly patterns...
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

  const getAnomalyLabelBadge = (label: string) => {
    switch (label) {
      case "ANOMALY":
        return {
          label: "ANOMALY",
          style: "bg-red-950/80 text-red-400 border-red-800",
          icon: ShieldAlert,
        };
      case "ELEVATED":
        return {
          label: "ELEVATED",
          style: "bg-amber-950/80 text-amber-400 border-amber-800",
          icon: AlertTriangle,
        };
      case "NORMAL":
      default:
        return {
          label: "NORMAL",
          style: "bg-emerald-950/80 text-emerald-400 border-emerald-800",
          icon: CheckCircle2,
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
              Security Intelligence & Anomaly Correlation Layer
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-sans">
            Deterministic pattern aggregation & ML anomaly detection derived exclusively from persisted findings & session evidence.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400 shrink-0">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>Active Intelligence Stream</span>
        </div>
      </div>

      {/* Top Executive Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Highest Risk */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg font-mono">
          <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
            <span>HIGHEST RISK SCORE</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold mb-2">
            <span className={getRiskScoreClass(risk_summary.highest_risk_score)}>
              {risk_summary.highest_risk_score}
            </span>
            <span className="text-xs text-slate-500 font-normal"> / 100</span>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {risk_summary.highest_risk_finding_id ? (
              <Link
                to={`/sessions/${risk_summary.highest_risk_session_id}?finding=${risk_summary.highest_risk_finding_id}`}
                className="text-cyan-400 hover:underline flex items-center gap-1"
              >
                <span>Ref: {risk_summary.highest_risk_finding_id}</span>
                <ExternalLink className="w-3 h-3" />
              </Link>
            ) : (
              "No Active Finding Risks"
            )}
          </div>
        </div>

        {/* Active Findings */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg font-mono">
          <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
            <span>ACTIVE FINDINGS</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mb-2">
            {risk_summary.active_findings_count}
          </div>
          <div className="text-[11px] text-slate-400">
            Across {risk_summary.affected_sessions_count} affected sessions
          </div>
        </div>

        {/* Pattern Concentration */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg font-mono">
          <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
            <span>REPEATED PATTERNS</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mb-2">
            {pattern_summary.repeated_rules.length}
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            Protocols: {pattern_summary.affected_protocols.join(", ") || "None"}
          </div>
        </div>

        {/* Priority Insights */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg font-mono">
          <div className="text-xs text-slate-400 mb-1 flex items-center justify-between">
            <span>PRIORITY INSIGHTS</span>
            <BrainCircuit className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mb-2">
            {insights.length}
          </div>
          <div className="text-[11px] text-slate-400">
            Deterministic correlation rules
          </div>
        </div>
      </div>

      {/* Protocol Exposure Matrix */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-lg space-y-4">
        <div className="flex items-center justify-between font-mono">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            Protocol Security Exposure Matrix
          </h3>
          <span className="text-[11px] text-slate-400">SMTP / IMAP / POP3 Assessment</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {protocol_exposure.map((item) => (
            <div
              key={item.protocol}
              className="p-4 bg-slate-950/80 border border-slate-800/80 rounded-lg space-y-3 font-mono"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-slate-100">{item.protocol}</span>
                <span className={`text-xs px-2 py-0.5 rounded border ${getRiskScoreClass(item.highest_risk_score)}`}>
                  Max Risk: {item.highest_risk_score}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs text-slate-400">
                <div>
                  <span className="text-slate-500">Sessions:</span> {item.total_sessions}
                </div>
                <div>
                  <span className="text-slate-500">Affected:</span> {item.affected_sessions}
                </div>
                <div>
                  <span className="text-slate-500">Findings:</span> {item.active_findings_count}
                </div>
                <div className="truncate">
                  <span className="text-slate-500">Dominant:</span>{" "}
                  <span className="text-slate-300">{item.dominant_rule_id || "None"}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* G4.2 — ML Anomaly Detection Section */}
      {anomalies && (
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-lg space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono pb-2 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-purple-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  ML-Assisted Anomaly Detection (Isolation Forest)
                </h3>
                <span className="px-2 py-0.5 bg-purple-950/80 text-purple-400 border border-purple-800 text-[10px] rounded font-semibold">
                  ADVISORY INTELLIGENCE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                Model: <span className="font-mono text-slate-300">{anomalies.model_version}</span> | Feature Set:{" "}
                <span className="font-mono text-slate-300">{anomalies.feature_version}</span>
              </p>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="text-slate-400">
                Analyzed: <span className="text-slate-100 font-bold">{anomalies.summary.total_sessions_analyzed}</span> sessions
              </div>
              <div className="text-red-400">
                Anomalous: <span className="font-bold">{anomalies.summary.anomalous_sessions_count}</span>
              </div>
              <div className="text-amber-400">
                Elevated: <span className="font-bold">{anomalies.summary.elevated_sessions_count}</span>
              </div>
            </div>
          </div>

          {/* Anomaly Results List */}
          {anomalies.results.length === 0 ? (
            <div className="p-6 bg-slate-950/60 border border-slate-800 rounded text-center font-mono text-xs text-slate-400">
              No sessions analyzed or all sessions conform to normal baseline characteristics.
            </div>
          ) : (
            <div className="space-y-3">
              {anomalies.results.map((res) => {
                const badge = getAnomalyLabelBadge(res.anomaly_label);
                const BadgeIcon = badge.icon;
                const hasCorroboration = res.supporting_finding_ids.length > 0;

                return (
                  <div
                    key={res.id}
                    className="p-4 bg-slate-950/90 border border-slate-800 rounded-lg space-y-3 font-mono"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 border text-xs font-bold rounded flex items-center gap-1 ${badge.style}`}>
                          <BadgeIcon className="w-3.5 h-3.5" />
                          {badge.label}
                        </span>

                        <span className="text-xs text-slate-300 font-bold">
                          Stream #{res.tcp_stream} ({res.protocol})
                        </span>

                        <span className="text-xs text-slate-400">
                          {res.src}:{res.src_port} → {res.dst}:{res.dst_port}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 text-xs">
                        {hasCorroboration && (
                          <span className="px-2 py-0.5 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded text-[10px] font-semibold flex items-center gap-1">
                            <Sparkles className="w-3 h-3 text-cyan-400" />
                            CORROBORATED BY FINDING
                          </span>
                        )}

                        <span className="text-slate-400">
                          Anomaly Score:{" "}
                          <span className="text-slate-100 font-bold">{res.anomaly_score}</span> / 100
                        </span>
                      </div>
                    </div>

                    <div className="text-xs text-slate-300 font-sans leading-relaxed">
                      {res.explanation}
                    </div>

                    {/* Associated Features Pills */}
                    {res.contributing_features.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px]">
                        <span className="text-slate-500 font-mono">Associated Features:</span>
                        {res.contributing_features.map((feat, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 bg-slate-900 border border-slate-800 text-slate-300 rounded"
                          >
                            {feat}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Action link to Session */}
                    <div className="pt-2 border-t border-slate-900 flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-500">
                        Evidence State: <span className="text-slate-400">{res.evidence_state}</span>
                      </span>

                      <Link
                        to={`/sessions/${res.session_id}${res.supporting_finding_ids.length > 0 ? `?finding=${res.supporting_finding_ids[0]}` : ""}`}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold"
                      >
                        <span>Inspect Session & Evidence</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Priority Intelligence Insights Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between font-mono">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <BrainCircuit className="w-4 h-4 text-cyan-400" />
            Prioritized Correlation Insights
          </h3>
          <span className="text-[11px] text-slate-400">Sorted by Severity & Risk</span>
        </div>

        {insights.length === 0 ? (
          <div className="p-8 bg-slate-950/60 border border-slate-800 rounded-lg text-center font-mono text-xs text-slate-400">
            No actionable intelligence insights or security pattern anomalies detected in this investigation.
          </div>
        ) : (
          <div className="space-y-4">
            {insights.map((insight) => {
              const evidenceBadge = getEvidenceStateBadge(insight.evidence_state);
              const EvidenceIcon = evidenceBadge.icon;

              return (
                <div
                  key={insight.id}
                  className="p-5 bg-slate-900/80 border border-slate-800 rounded-lg space-y-4 font-mono hover:border-slate-700 transition-colors"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityClass(insight.severity as FindingSeverity)}`}>
                          {getSeverityLabel(insight.severity as FindingSeverity)}
                        </span>

                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${evidenceBadge.style} flex items-center gap-1`}>
                          <EvidenceIcon className="w-3 h-3" />
                          {evidenceBadge.label}
                        </span>

                        <span className="text-xs text-slate-400 font-mono">
                          ID: {insight.id}
                        </span>
                      </div>

                      <h4 className="text-sm font-bold text-slate-100 font-sans pt-1">
                        {insight.title}
                      </h4>
                    </div>

                    <div className="text-right shrink-0">
                      <div className="text-xs text-slate-400">Derived Risk</div>
                      <div className={`text-lg font-bold ${getRiskScoreClass(insight.risk_score)}`}>
                        {insight.risk_score} <span className="text-xs font-normal text-slate-500">/ 100</span>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 font-sans leading-relaxed">
                    {insight.description}
                  </p>

                  {insight.remediation && (
                    <div className="p-3 bg-slate-950/80 border border-slate-800 rounded flex items-start gap-2.5 text-xs text-slate-300 font-sans">
                      <Wrench className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold text-cyan-300 font-mono">Remediation Guidance: </span>
                        {insight.remediation}
                      </div>
                    </div>
                  )}

                  {/* Supporting Evidence Provenance */}
                  <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
                    <div className="flex flex-wrap items-center gap-4 text-slate-400">
                      <div>
                        Findings: <span className="text-slate-200 font-bold">{insight.supporting_finding_ids.length}</span>
                      </div>
                      <div>
                        Sessions: <span className="text-slate-200 font-bold">{insight.supporting_session_ids.length}</span>
                      </div>
                      {insight.supporting_frame_numbers.length > 0 && (
                        <div className="truncate max-w-xs">
                          Frames: <span className="text-slate-200">{insight.supporting_frame_numbers.slice(0, 5).join(", ")}{insight.supporting_frame_numbers.length > 5 ? "..." : ""}</span>
                        </div>
                      )}
                    </div>

                    {insight.supporting_session_ids.length > 0 && (
                      <Link
                        to={`/sessions/${insight.supporting_session_ids[0]}${insight.supporting_finding_ids.length > 0 ? `?finding=${insight.supporting_finding_ids[0]}` : ""}`}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold transition-colors"
                      >
                        <span>Inspect Primary Session Evidence</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
