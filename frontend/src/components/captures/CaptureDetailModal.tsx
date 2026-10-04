import React, { useState } from "react";
import { X, HardDrive, Copy, Check, FileCode, Clock, Activity, Layers, ExternalLink } from "lucide-react";
import { CaptureResponse } from "../../types/api";
import { formatTimestamp, formatBytes } from "../../utils/formatting";

interface CaptureDetailModalProps {
  capture: CaptureResponse | null;
  onClose: () => void;
  onNavigateToSessions?: (captureId: string) => void;
}

export const CaptureDetailModal: React.FC<CaptureDetailModalProps> = ({
  capture,
  onClose,
  onNavigateToSessions,
}) => {
  const [copied, setCopied] = useState(false);

  if (!capture) return null;

  const handleCopyHash = () => {
    navigator.clipboard.writeText(capture.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 font-sans"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div
        className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl max-w-2xl w-full overflow-hidden text-slate-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-cyan-400" />
            <h2 id="modal-title" className="text-sm font-mono font-bold uppercase text-slate-100 tracking-wider">
              Capture Provenance Details
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors"
            aria-label="Close capture details modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 max-h-[80vh] overflow-y-auto font-mono text-xs">
          {/* Section 1: Content Identity */}
          <div className="bg-slate-950/50 p-4 rounded-lg border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="font-bold text-slate-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <FileCode className="w-4 h-4 text-cyan-400" /> Cryptographic Identity
              </span>
              <span className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] font-bold border border-slate-700">
                {capture.format}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-slate-500 text-[11px] mb-1">Capture ID</div>
                <div className="text-cyan-400 font-bold text-sm">{capture.id}</div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px] mb-1">Original Filename</div>
                <div className="text-slate-100 font-bold text-sm truncate" title={capture.filename}>
                  {capture.filename}
                </div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px] mb-1">File Size</div>
                <div className="text-slate-200 font-semibold">{formatBytes(capture.bytes)}</div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px] mb-1">Investigation ID</div>
                <div className="text-slate-300">{capture.investigation_id}</div>
              </div>
            </div>

            {/* SHA-256 Box */}
            <div className="pt-2">
              <div className="text-slate-500 text-[11px] mb-1 flex items-center justify-between">
                <span>Content SHA-256 Hash</span>
                <span className="text-[10px] text-slate-500">64-char Hexadecimal</span>
              </div>
              <div className="flex items-center gap-2 bg-slate-900 p-2.5 rounded border border-slate-800">
                <code className="text-slate-200 text-[11px] break-all select-all flex-1">
                  {capture.sha256}
                </code>
                <button
                  onClick={handleCopyHash}
                  className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition-colors shrink-0"
                  title="Copy full SHA-256 hash"
                  aria-label="Copy full SHA-256 hash"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>

          {/* Section 2: Analysis Lifecycle */}
          <div className="bg-slate-950/50 p-4 rounded-lg border border-slate-800 space-y-3">
            <span className="font-bold text-slate-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5 border-b border-slate-800/80 pb-2">
              <Clock className="w-4 h-4 text-cyan-400" /> Analysis Lifecycle & Job Status
            </span>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-slate-500 text-[11px] mb-1">Upload Timestamp</div>
                <div className="text-slate-200">{formatTimestamp(capture.uploaded_at)}</div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px] mb-1">Analysis Job ID</div>
                <div className="text-slate-300">{capture.job_id || "N/A"}</div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px] mb-1">Analysis Status</div>
                <div>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      capture.status === "COMPLETED"
                        ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/80"
                        : capture.status === "PROCESSING" || capture.status === "QUEUED"
                        ? "bg-cyan-950/80 text-cyan-400 border border-cyan-800/80"
                        : "bg-red-950/80 text-red-400 border border-red-800/80"
                    }`}
                  >
                    {capture.status || "COMPLETED"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Section 3: Derived Evidence */}
          <div className="bg-slate-950/50 p-4 rounded-lg border border-slate-800 space-y-3">
            <span className="font-bold text-slate-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5 border-b border-slate-800/80 pb-2">
              <Layers className="w-4 h-4 text-cyan-400" /> Derived Evidence Sessions
            </span>

            <div className="flex items-center justify-between">
              <div>
                <div className="text-slate-200 font-bold text-sm">
                  {capture.sessions_count ?? 0} Forensic Sessions Extracted
                </div>
                <div className="text-slate-500 text-[11px] mt-0.5">
                  Protocol sessions parsed from TCP streams in this capture
                </div>
              </div>
              {onNavigateToSessions && (
                <button
                  onClick={() => {
                    onClose();
                    onNavigateToSessions(capture.id);
                  }}
                  className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded font-semibold text-xs transition-colors flex items-center gap-1.5"
                >
                  <Activity className="w-3.5 h-3.5" /> View Sessions <ExternalLink className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-slate-950/80 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-mono text-xs transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
