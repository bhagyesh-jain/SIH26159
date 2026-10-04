import React, { useState } from "react";
import { HardDrive, Copy, Check, Info, FileCode } from "lucide-react";
import { CaptureResponse } from "../../types/api";
import { formatBytes } from "../../utils/formatting";

interface CaptureTableProps {
  captures: CaptureResponse[];
  loading?: boolean;
  onSelectCapture?: (capture: CaptureResponse) => void;
}

export const CaptureTable: React.FC<CaptureTableProps> = ({
  captures,
  loading = false,
  onSelectCapture,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopyHash = (hash: string, captureId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedId(captureId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const truncateHash = (hash: string) => {
    if (!hash || hash.length <= 16) return hash;
    return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
  };

  if (loading) {
    return (
      <div className="p-8 bg-slate-900/60 border border-slate-800 rounded-lg text-center font-mono text-xs text-slate-400">
        Loading source capture files and evidence provenance...
      </div>
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-sans">
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-cyan-400" /> Source PCAP Captures ({captures.length})
        </h3>
        <span className="text-[11px] font-mono text-slate-500">
          First-class forensic content identity
        </span>
      </div>

      {captures.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-slate-500 bg-slate-900/40">
          No source capture files uploaded for this investigation case.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950/90 text-slate-400 border-b border-slate-800">
                <th className="py-2.5 px-4 font-semibold">Capture ID</th>
                <th className="py-2.5 px-4 font-semibold">Filename</th>
                <th className="py-2.5 px-4 font-semibold">Format</th>
                <th className="py-2.5 px-4 font-semibold">Size</th>
                <th className="py-2.5 px-4 font-semibold">Content SHA-256</th>
                <th className="py-2.5 px-4 font-semibold">Status</th>
                <th className="py-2.5 px-4 font-semibold text-right">Sessions</th>
                <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {captures.map((c) => (
                <tr
                  key={c.id}
                  className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  onClick={() => onSelectCapture && onSelectCapture(c)}
                >
                  <td className="py-2.5 px-4 text-cyan-400 font-bold">{c.id}</td>
                  <td className="py-2.5 px-4 font-bold text-slate-100 flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span>{c.filename}</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[11px] font-bold border border-slate-700">
                      {c.format}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-300">{formatBytes(c.bytes)}</td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-1.5">
                      <code
                        className="text-slate-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-[11px]"
                        title={c.sha256}
                      >
                        {truncateHash(c.sha256)}
                      </code>
                      <button
                        onClick={(e) => handleCopyHash(c.sha256, c.id, e)}
                        className="p-1 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded transition-colors"
                        title="Copy full Content SHA-256 hash"
                        aria-label={`Copy SHA-256 hash for ${c.filename}`}
                      >
                        {copiedId === c.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </td>
                  <td className="py-2.5 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        c.status === "COMPLETED"
                          ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/80"
                          : c.status === "PROCESSING" || c.status === "QUEUED"
                          ? "bg-cyan-950/80 text-cyan-400 border border-cyan-800/80"
                          : "bg-red-950/80 text-red-400 border border-red-800/80"
                      }`}
                    >
                      {c.status || "COMPLETED"}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right font-bold text-slate-100">
                    {c.sessions_count ?? "—"}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={() => onSelectCapture && onSelectCapture(c)}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-mono transition-colors inline-flex items-center gap-1"
                    >
                      <Info className="w-3 h-3" /> Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
