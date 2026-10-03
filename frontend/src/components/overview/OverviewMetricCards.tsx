import React from "react";
import { Activity, ShieldAlert, AlertOctagon, CheckCircle2 } from "lucide-react";
import { InvestigationSummaryTotals, ProtocolBreakdown } from "../../types/api";
import { getRiskScoreClass } from "../../utils/risk";

interface OverviewMetricCardsProps {
  totals: InvestigationSummaryTotals;
  protocolBreakdown: ProtocolBreakdown;
}

export const OverviewMetricCards: React.FC<OverviewMetricCardsProps> = ({
  totals,
  protocolBreakdown,
}) => {
  const riskClass = getRiskScoreClass(totals.highest_risk_score);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
      {/* 1. Analyzed Sessions */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
            Analyzed Sessions
          </span>
          <Activity className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-2xl font-bold text-slate-100 mb-2">
          {totals.sessions_count}
        </div>
        <div className="text-[11px] text-slate-400 flex items-center gap-1.5 flex-wrap">
          <span className="text-cyan-400">SMTP: {protocolBreakdown.smtp_sessions}</span>
          <span>•</span>
          <span className="text-cyan-400">IMAP: {protocolBreakdown.imap_sessions}</span>
          <span>•</span>
          <span className="text-cyan-400">POP3: {protocolBreakdown.pop3_sessions}</span>
        </div>
      </div>

      {/* 2. Actionable Findings */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
            Actionable Findings
          </span>
          <ShieldAlert className="w-4 h-4 text-amber-400" />
        </div>
        <div className="text-2xl font-bold text-amber-400 mb-2">
          {totals.actionable_findings_count}
        </div>
        <div className="text-[11px] text-slate-400">
          Affecting <span className="text-slate-200 font-bold">{totals.affected_sessions_count}</span> session{totals.affected_sessions_count === 1 ? "" : "s"}
        </div>
      </div>

      {/* 3. Highest Risk Priority Score */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
            Highest Risk Priority
          </span>
          <AlertOctagon className="w-4 h-4 text-red-400" />
        </div>
        <div className="flex items-baseline gap-2 mb-2">
          <span className={`text-2xl font-bold ${riskClass}`}>
            {totals.highest_risk_score}
          </span>
          <span className="text-xs text-slate-500">/ 100</span>
        </div>
        <div className="text-[10px] text-slate-500 tracking-tight">
          Evidence-Adjusted Risk Priority Score
        </div>
      </div>

      {/* 4. Verified Baselines */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
            Verified Baselines
          </span>
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-2xl font-bold text-emerald-400 mb-2">
          {totals.informational_findings_count}
        </div>
        <div className="text-[11px] text-slate-400">
          Informational Secure Observations
        </div>
      </div>
    </div>
  );
};
