import React from "react";
import { X, Shield, Clock, Layers, FileCode, CheckCircle2 } from "lucide-react";
import { SecurityEventResponse } from "../../types/api";
import { formatTimestamp, formatFrameNumbers } from "../../utils/formatting";

interface SecurityEventDetailModalProps {
  event: SecurityEventResponse | null;
  onClose: () => void;
}

export const SecurityEventDetailModal: React.FC<SecurityEventDetailModalProps> = ({
  event,
  onClose,
}) => {
  if (!event) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-lg w-full max-w-2xl shadow-2xl overflow-hidden font-sans">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-950/80">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-semibold font-mono text-slate-100">
              Security Event: {event.event_type}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4 text-xs font-mono">
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3 rounded border border-slate-800">
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Event ID</span>
              <span className="text-slate-200 font-bold">{event.id}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Protocol</span>
              <span className="text-cyan-400 font-bold">{event.protocol}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Upgrade Status</span>
              <span className="text-emerald-400 font-bold">{event.upgrade_status || "—"}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Completeness</span>
              <span className="text-slate-300">{event.completeness_status || "COMPLETE"}</span>
            </div>
          </div>

          {/* Evidence Provenance & Timing */}
          <div className="bg-slate-950 p-3 rounded border border-slate-800 space-y-2">
            <span className="text-slate-400 block text-[11px] font-bold uppercase tracking-wider">
              Evidence Provenance & Frame Metadata
            </span>
            <div className="flex flex-wrap items-center gap-4 text-slate-300">
              <div className="flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Frames: {formatFrameNumbers(event.frame_numbers)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                <span>Time: {formatTimestamp(event.timestamp)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Source: {event.evidence_source || "TSHARK_REASSEMBLED_STREAM"}</span>
              </div>
            </div>
          </div>

          {/* Observed Wire Payload Value */}
          <div>
            <span className="text-slate-400 block mb-1 font-bold uppercase text-[11px] tracking-wider">
              Observed Wire Payload Value:
            </span>
            <div className="bg-slate-950 p-3 rounded border border-slate-800 text-cyan-300 break-all">
              {event.observed_value || "—"}
            </div>
          </div>

          {/* Structured Event Details */}
          {event.details && Object.keys(event.details).length > 0 && (
            <div>
              <span className="text-slate-400 block mb-1 font-bold uppercase text-[11px] tracking-wider flex items-center gap-1">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" /> Structured Event Details:
              </span>
              <pre className="bg-slate-950 p-3 rounded border border-slate-800 text-slate-300 overflow-x-auto text-[11px]">
                {JSON.stringify(event.details, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end px-5 py-3 border-t border-slate-800 bg-slate-950/60">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded transition-colors"
          >
            Close Event Detail
          </button>
        </div>
      </div>
    </div>
  );
};
