import React from "react";
import { ShieldAlert, ArrowUpRight } from "lucide-react";
import { FindingResponse } from "../../types/api";
import {
  getSeverityLabel,
  getSeverityClass,
  getConfidenceLabel,
  getRiskScoreClass,
} from "../../utils/risk";
import { EmptyState } from "../common/EmptyState";

interface SessionFindingsTableProps {
  findings: FindingResponse[];
  loading?: boolean;
  onSelectFinding: (finding: FindingResponse) => void;
  onSelectFrame?: (frameNumber: number) => void;
}

export const SessionFindingsTable: React.FC<SessionFindingsTableProps> = ({
  findings,
  onSelectFinding,
  onSelectFrame,
}) => {
  if (!findings || findings.length === 0) {
    return (
      <EmptyState
        title="No Security Findings Generated"
        description="No deterministic rule findings were produced for this session stream."
      />
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-sans">
      <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" /> Deterministic Security Findings ({findings.length})
        </h3>
        <span className="text-[11px] font-mono text-slate-500">
          Click row to open forensic evidence detail panel
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="bg-slate-950/90 text-slate-400 border-b border-slate-800">
              <th className="py-2.5 px-4 font-semibold">Severity</th>
              <th className="py-2.5 px-4 font-semibold">Finding Title</th>
              <th className="py-2.5 px-4 font-semibold">Rule ID</th>
              <th className="py-2.5 px-4 font-semibold">Confidence</th>
              <th className="py-2.5 px-4 font-semibold text-right">Risk Score</th>
              <th className="py-2.5 px-4 font-semibold">Evidence Frames</th>
              <th className="py-2.5 px-4 font-semibold text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-200">
            {findings.map((f) => {
              const severityClass = getSeverityClass(f.severity);
              const severityLabel = getSeverityLabel(f.severity);
              const confidenceLabel = getConfidenceLabel(f.confidence);
              const riskClass = getRiskScoreClass(f.risk_score);

              return (
                <tr
                  key={f.id}
                  onClick={() => onSelectFinding(f)}
                  className="hover:bg-slate-800/50 transition-colors cursor-pointer group"
                >
                  <td className="py-3 px-4">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${severityClass}`}
                    >
                      {severityLabel}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors">
                    {f.title}
                  </td>
                  <td className="py-3 px-4 text-cyan-400 font-bold">{f.rule_id}</td>
                  <td className="py-3 px-4 text-slate-400">{confidenceLabel}</td>
                  <td className={`py-3 px-4 text-right ${riskClass}`}>
                    {f.risk_score}
                  </td>
                  <td className="py-3 px-4">
                    {f.evidence_frame_numbers && f.evidence_frame_numbers.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {f.evidence_frame_numbers.map((frame) => (
                          <button
                            key={frame}
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onSelectFrame) onSelectFrame(frame);
                            }}
                            className="px-1.5 py-0.5 bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 rounded text-[10px] font-bold transition-colors"
                          >
                            #{frame}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding(f);
                      }}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 text-slate-300 border border-slate-700 hover:border-cyan-700 rounded text-[11px] font-mono transition-all inline-flex items-center gap-1"
                    >
                      Inspect <ArrowUpRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
