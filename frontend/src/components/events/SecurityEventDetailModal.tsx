import React from "react";
import { X, Shield, Clock, Layers } from "lucide-react";
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
              <span className="text-emerald-400 font-bold">{event.upgrade_status || "N/A"}</span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block text-[10px]">Completeness</span>
              <span className="text-slate-300">{event.completeness_status}</span>
            </div>
          </div>

          <div>
            <span className="text-slate-400 block mb-1">Supporting Frames & Timestamp:</span>
            <div className="flex items-center gap-3 text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-800">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>{formatFrameNumbers(event.frame_numbers)}</span>
              <span>•</span>
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>{formatTimestamp(event.timestamp)}</span>
            </div>
          </div>

          <div>
            <span className="text-slate-400 block mb-1">Observed Payload Value:</span>
            <div className="bg-slate-950 p-3 rounded border border-slate-800 text-cyan-300 break-all">
              {event.observed_value || "—"}
            </div>
          </div>

          {event.details && Object.keys(event.details).length > 0 && (
            <div>
              <span className="text-slate-400 block mb-1">Structured Event Details:</span>
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
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
