import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert, ArrowUpRight, Eye } from "lucide-react";
import { FindingResponse } from "../../types/api";
import { getSeverityClass, getRiskScoreClass } from "../../utils/risk";
import { FindingDetailPanel } from "../findings/FindingDetailPanel";

interface TopFindingsCardProps {
  findings: FindingResponse[];
}

export const TopFindingsCard: React.FC<TopFindingsCardProps> = ({ findings }) => {
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);

  // Filter active non-info findings or top risk findings
  const topActive = findings
    .filter((f) => f.status === "ACTIVE" && f.severity !== "INFO")
    .slice(0, 5);

  if (topActive.length === 0) {
    return null;
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-sans">
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400" /> Priority Triage Action Items
        </h3>
        <span className="text-[10px] font-mono text-slate-500">Sorted by Risk Priority Score</span>
      </div>

      <div className="divide-y divide-slate-800/60 font-mono text-xs">
        {topActive.map((f) => {
          const firstFrame = f.evidence_frame_numbers?.[0];
          return (
            <div
              key={f.id}
              className="p-3.5 hover:bg-slate-800/40 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityClass(f.severity)}`}>
                    {f.severity}
                  </span>
                  <button
                    onClick={() => setSelectedFinding(f)}
                    className="font-bold text-slate-100 text-xs hover:text-cyan-400 text-left transition-colors"
                  >
                    {f.title}
                  </button>
                  <span className="text-cyan-400 text-[11px]">({f.protocol})</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Rule ID: <code className="text-slate-300">{f.rule_id}</code> • Stream: <code className="text-slate-300">{f.session_id}</code>
                </div>
              </div>

              <div className="flex items-center gap-2.5 self-end sm:self-auto flex-shrink-0">
                <div className="text-right pr-2">
                  <div className="text-[10px] text-slate-500 uppercase">Risk Score</div>
                  <div className={`text-sm font-bold ${getRiskScoreClass(f.risk_score)}`}>
                    {f.risk_score}
                  </div>
                </div>

                <button
                  onClick={() => setSelectedFinding(f)}
                  className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs transition-colors inline-flex items-center gap-1"
                >
                  <Eye className="w-3.5 h-3.5 text-slate-400" /> Detail
                </button>

                <Link
                  to={`/sessions/${f.session_id}${firstFrame ? `?frame=${firstFrame}&finding=${f.id}` : `?finding=${f.id}`}`}
                  className="px-2.5 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 rounded text-xs font-bold transition-colors inline-flex items-center gap-1"
                >
                  Inspect Stream <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>

      {/* Finding Detail Panel Drawer */}
      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
};
