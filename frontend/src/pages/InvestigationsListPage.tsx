import React, { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { Plus, ArrowRight, Clock, ShieldCheck } from "lucide-react";
import { listInvestigations } from "../api/investigations";
import { InvestigationResponse } from "../types/api";
import { formatTimestamp } from "../utils/formatting";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingState } from "../components/common/LoadingState";
import { ErrorState } from "../components/common/ErrorState";
import { EmptyState } from "../components/common/EmptyState";
import { CreateInvestigationModal } from "../components/investigations/CreateInvestigationModal";

export const InvestigationsListPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<InvestigationResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchInvestigations = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listInvestigations();
      setInvestigations(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to load investigation cases.");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInvestigations();
  }, [fetchInvestigations]);

  return (
    <div>
      <PageHeader
        title="Forensic Investigations"
        description="Active email cryptographic assessment cases and PCAP stream ingestion management."
        actions={
          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold rounded transition-colors flex items-center gap-2 shadow-lg shadow-cyan-950/50"
          >
            <Plus className="w-4 h-4" /> New Investigation
          </button>
        }
      />

      {loading ? (
        <LoadingState message="Loading active forensic investigation cases..." />
      ) : error ? (
        <ErrorState message={error} onRetry={fetchInvestigations} />
      ) : investigations.length === 0 ? (
        <EmptyState
          title="No Active Investigations"
          description="Create a new investigation case to start analyzing email traffic PCAP captures."
          action={
            <button
              onClick={() => setIsModalOpen(true)}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold rounded transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" /> Create First Investigation
            </button>
          }
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {investigations.map((inv) => (
            <div
              key={inv.id}
              className="bg-slate-900 border border-slate-800 rounded-lg p-5 hover:border-slate-700 transition-all flex flex-col justify-between group"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                    {inv.id}
                  </span>
                  <span className="inline-flex items-center gap-1 text-[11px] font-mono font-semibold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                    <ShieldCheck className="w-3 h-3" /> {inv.status}
                  </span>
                </div>

                <h3 className="text-base font-semibold font-mono text-slate-100 group-hover:text-cyan-300 transition-colors">
                  {inv.title}
                </h3>

                <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mt-3">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  <span>Created: {formatTimestamp(inv.created_at)}</span>
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-end">
                <Link
                  to={`/investigations/${inv.id}`}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 text-slate-200 rounded border border-slate-700 hover:border-cyan-700 text-xs font-mono font-medium transition-all"
                >
                  Open Workspace <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Modal for creating a new investigation */}
      <CreateInvestigationModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onCreated={() => {
          fetchInvestigations();
        }}
      />
    </div>
  );
};
