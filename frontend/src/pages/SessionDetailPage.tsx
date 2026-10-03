import React from "react";
import { useParams } from "react-router-dom";
import { PageHeader } from "../components/common/PageHeader";
import { Network } from "lucide-react";

export const SessionDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  return (
    <div>
      <PageHeader
        title={`TCP Session Stream: ${id || "Unknown"}`}
        description="Reassembled packet event timeline, STARTTLS state progression, and TLS analysis."
      />
      <div className="p-8 bg-slate-900/40 border border-slate-800 rounded-lg text-center font-mono">
        <Network className="w-10 h-10 text-cyan-500 mx-auto mb-3 opacity-80" />
        <h3 className="text-base font-semibold text-slate-200">
          Session Stream Placeholder
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
          Current Session ID: <code className="text-cyan-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">{id}</code>
        </p>
        <p className="text-xs text-slate-500 mt-3">
          Stage G1 Foundation active. Packet event timeline and evidence matrix will be assembled in Stage G3.
        </p>
      </div>
    </div>
  );
};
