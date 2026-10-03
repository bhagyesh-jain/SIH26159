import React from "react";
import { CheckCircle2, AlertCircle, Info } from "lucide-react";
import { EvidenceQualitySummary } from "../../types/api";

interface EvidenceQualityPanelProps {
  evidenceQuality: EvidenceQualitySummary;
}

export const EvidenceQualityPanel: React.FC<EvidenceQualityPanelProps> = ({
  evidenceQuality,
}) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <h3 className="text-xs font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400" /> Forensic Evidence Quality & Completeness
        </h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Stream Completeness */}
        <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-2">
          <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">
            TCP Stream Reassembly State
          </span>
          <div className="flex items-center justify-between text-slate-200">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" /> Complete Reassembled Streams:
            </span>
            <span className="font-bold">{evidenceQuality.complete_sessions}</span>
          </div>
          <div className="flex items-center justify-between text-slate-200">
            <span className="flex items-center gap-1.5 text-amber-400">
              <AlertCircle className="w-3.5 h-3.5" /> Truncated / Incomplete Streams:
            </span>
            <span className="font-bold">{evidenceQuality.incomplete_sessions}</span>
          </div>
        </div>

        {/* Finding Confidence Distribution */}
        <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-2">
          <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">
            Finding Confidence Classification
          </span>
          <div className="flex items-center justify-between text-slate-200">
            <span>High Confidence (Direct Wire Evidence):</span>
            <span className="font-bold text-emerald-400">{evidenceQuality.high_confidence_findings}</span>
          </div>
          <div className="flex items-center justify-between text-slate-200">
            <span>Medium Confidence (Wire Alert Codes):</span>
            <span className="font-bold text-amber-400">{evidenceQuality.medium_confidence_findings}</span>
          </div>
          <div className="flex items-center justify-between text-slate-200">
            <span>Low / Unknown Confidence:</span>
            <span className="font-bold text-slate-400">{evidenceQuality.low_or_unknown_confidence_findings}</span>
          </div>
        </div>
      </div>

      {/* Forensic Disclaimer */}
      <div className="p-2.5 bg-slate-950/60 border border-slate-800 rounded text-[11px] text-slate-400 flex items-start gap-2">
        <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
        <span>
          Metrics reflect observable PCAP/PCAPNG packet evidence extracted via TShark stream reassembly.
          Encrypted TLS 1.3 payloads without session keys represent passive observation boundaries.
        </span>
      </div>
    </div>
  );
};
