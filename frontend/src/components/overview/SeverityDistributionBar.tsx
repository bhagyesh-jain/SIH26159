import React from "react";
import { BarChart2 } from "lucide-react";
import { SeverityBreakdown } from "../../types/api";

interface SeverityDistributionBarProps {
  breakdown: SeverityBreakdown;
}

export const SeverityDistributionBar: React.FC<SeverityDistributionBarProps> = ({ breakdown }) => {
  const total =
    breakdown.critical + breakdown.high + breakdown.medium + breakdown.low + breakdown.info;

  const categories = [
    { label: "CRITICAL", count: breakdown.critical, color: "bg-red-500", text: "text-red-400" },
    { label: "HIGH", count: breakdown.high, color: "bg-amber-500", text: "text-amber-400" },
    { label: "MEDIUM", count: breakdown.medium, color: "bg-yellow-500", text: "text-yellow-400" },
    { label: "LOW", count: breakdown.low, color: "bg-blue-500", text: "text-blue-400" },
    { label: "INFO", count: breakdown.info, color: "bg-emerald-500", text: "text-emerald-400" },
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs space-y-3">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h3 className="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <BarChart2 className="w-4 h-4 text-cyan-400" /> Active Severity Distribution
        </h3>
        <span className="text-slate-400 text-[11px]">Total Active: {total}</span>
      </div>

      {/* Visual Stacked Bar */}
      <div className="h-3 w-full bg-slate-950 rounded overflow-hidden flex">
        {total === 0 ? (
          <div className="w-full bg-slate-800 text-[9px] text-slate-500 flex items-center justify-center font-mono">
            No active findings
          </div>
        ) : (
          categories.map((cat) => {
            if (cat.count === 0) return null;
            const pct = (cat.count / total) * 100;
            return (
              <div
                key={cat.label}
                style={{ width: `${pct}%` }}
                className={`${cat.color} h-full transition-all`}
                title={`${cat.label}: ${cat.count} (${pct.toFixed(1)}%)`}
              />
            );
          })
        )}
      </div>

      {/* Severity Breakdown Legend */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1">
        {categories.map((cat) => {
          const pct = total > 0 ? ((cat.count / total) * 100).toFixed(1) : "0.0";
          return (
            <div key={cat.label} className="bg-slate-950 p-2 rounded border border-slate-800/80">
              <div className="flex items-center justify-between mb-1">
                <span className={`font-bold text-[11px] ${cat.text}`}>{cat.label}</span>
                <span className="text-slate-200 font-bold">{cat.count}</span>
              </div>
              <div className="text-[10px] text-slate-500">{pct}%</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
