import React from "react";
import { Link } from "react-router-dom";
import { Network, ArrowRight, Activity } from "lucide-react";
import { SessionResponse } from "../../types/api";
import { formatAddress, formatProtocol } from "../../utils/formatting";
import { EmptyState } from "../common/EmptyState";
import { LoadingState } from "../common/LoadingState";

interface SessionTableProps {
  sessions: SessionResponse[];
  loading?: boolean;
}

export const SessionTable: React.FC<SessionTableProps> = ({
  sessions,
  loading = false,
}) => {
  if (loading) {
    return <LoadingState message="Loading TCP streams & protocol sessions..." />;
  }

  if (!sessions || sessions.length === 0) {
    return (
      <EmptyState
        title="No TCP Streams Ingested"
        description="Upload a PCAP or PCAPNG file above to extract email sessions and protocol state machines."
      />
    );
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-sans">
      <div className="px-5 py-3.5 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" /> Extracted TCP Streams ({sessions.length})
        </h3>
        <span className="text-[11px] font-mono text-slate-500">
          Click stream row for packet timeline & evidence
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="bg-slate-950/90 text-slate-400 border-b border-slate-800">
              <th className="py-2.5 px-4 font-semibold">Stream ID</th>
              <th className="py-2.5 px-4 font-semibold">Protocol</th>
              <th className="py-2.5 px-4 font-semibold">Source (Client)</th>
              <th className="py-2.5 px-4 font-semibold">Destination (Server)</th>
              <th className="py-2.5 px-4 font-semibold">Completeness</th>
              <th className="py-2.5 px-4 font-semibold text-right">Events Count</th>
              <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-200">
            {sessions.map((s) => {
              const proto = formatProtocol(s.protocol);
              let protoColor = "bg-slate-800 text-slate-300 border-slate-700";
              if (proto === "SMTP") protoColor = "bg-cyan-950/80 text-cyan-400 border-cyan-800/60";
              if (proto === "IMAP") protoColor = "bg-indigo-950/80 text-indigo-400 border-indigo-800/60";
              if (proto === "POP3") protoColor = "bg-purple-950/80 text-purple-400 border-purple-800/60";

              return (
                <tr
                  key={s.id}
                  className="hover:bg-slate-800/40 transition-colors group"
                >
                  <td className="py-3 px-4 text-slate-300 font-bold">
                    Stream #{s.tcp_stream ?? "—"}
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${protoColor}`}
                    >
                      {proto}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    {formatAddress(s.src, s.src_port)}
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    {formatAddress(s.dst, s.dst_port)}
                  </td>
                  <td className="py-3 px-4">
                    <span className="inline-flex items-center gap-1 text-[11px] text-slate-400">
                      <Activity className="w-3 h-3 text-cyan-500" />
                      {s.completeness || "COMPLETE"}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right text-slate-300">
                    {s.events_count ?? 0}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <Link
                      to={`/sessions/${s.id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 text-slate-300 rounded border border-slate-700 hover:border-cyan-700 text-[11px] font-mono font-medium transition-all"
                    >
                      View Timeline <ArrowRight className="w-3 h-3" />
                    </Link>
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
