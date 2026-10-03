import React, { useState, useEffect, useRef, useCallback } from "react";
import { Shield, Filter, Eye, RefreshCw, AlertCircle } from "lucide-react";
import { SecurityEventResponse, SecurityEventQueryParams } from "../../types/api";
import { formatFrameNumbers } from "../../utils/formatting";
import { EmptyState } from "../common/EmptyState";
import { SecurityEventDetailModal } from "./SecurityEventDetailModal";

interface SecurityEventsTableProps {
  events: SecurityEventResponse[];
  loading?: boolean;
  error?: string | null;
  onFilterChange?: (filters: SecurityEventQueryParams) => void;
}

export const SecurityEventsTable: React.FC<SecurityEventsTableProps> = ({
  events,
  loading = false,
  error = null,
  onFilterChange,
}) => {
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [upgradeStatusFilter, setUpgradeStatusFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventResponse | null>(null);

  const debounceTimerRef = useRef<NodeJS.Timeout | null>(null);

  const triggerFilterChange = useCallback(
    (eType: string, uStatus: string, proto: string) => {
      if (!onFilterChange) return;
      onFilterChange({
        event_type: eType.trim() || undefined,
        upgrade_status: uStatus.trim() || undefined,
        protocol: proto.trim() || undefined,
        limit: 100,
        offset: 0,
      });
    },
    [onFilterChange]
  );

  const handleEventTypeChange = (val: string) => {
    setEventTypeFilter(val);
    if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    debounceTimerRef.current = setTimeout(() => {
      triggerFilterChange(val, upgradeStatusFilter, protocolFilter);
    }, 300);
  };

  const handleUpgradeStatusChange = (val: string) => {
    setUpgradeStatusFilter(val);
    if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    debounceTimerRef.current = setTimeout(() => {
      triggerFilterChange(eventTypeFilter, val, protocolFilter);
    }, 300);
  };

  const handleProtocolChange = (val: string) => {
    setProtocolFilter(val);
    if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    triggerFilterChange(eventTypeFilter, upgradeStatusFilter, val);
  };

  useEffect(() => {
    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
  }, []);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden font-sans">
      {/* Header & Filter Controls */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" /> Persisted Security Events ({events.length})
          {loading && <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin ml-2" />}
        </h3>

        <div className="flex items-center gap-2 font-mono text-xs flex-wrap">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          
          {/* Protocol Filter */}
          <select
            value={protocolFilter}
            onChange={(e) => handleProtocolChange(e.target.value)}
            aria-label="Filter Protocol"
            className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
          >
            <option value="">All Protocols</option>
            <option value="SMTP">SMTP</option>
            <option value="IMAP">IMAP</option>
            <option value="POP3">POP3</option>
            <option value="TLS">TLS</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>

          {/* Event Type Filter */}
          <input
            type="text"
            placeholder="Filter Event Type..."
            value={eventTypeFilter}
            onChange={(e) => handleEventTypeChange(e.target.value)}
            className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 w-36"
          />

          {/* Upgrade Status Filter */}
          <input
            type="text"
            placeholder="Filter Status..."
            value={upgradeStatusFilter}
            onChange={(e) => handleUpgradeStatusChange(e.target.value)}
            className="px-2.5 py-1 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 w-32"
          />
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-3 bg-red-950/50 border-b border-red-800/60 text-red-300 text-xs font-mono flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <span>Failed to query security events: {error}</span>
        </div>
      )}

      {/* Table Content */}
      {events.length === 0 ? (
        <EmptyState
          title="No Security Events Matched"
          description="No persisted security events match the backend filter criteria."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950/90 text-slate-400 border-b border-slate-800">
                <th className="py-2.5 px-4 font-semibold">Event ID</th>
                <th className="py-2.5 px-4 font-semibold">Event Type</th>
                <th className="py-2.5 px-4 font-semibold">Protocol</th>
                <th className="py-2.5 px-4 font-semibold">Upgrade Status</th>
                <th className="py-2.5 px-4 font-semibold">Frames</th>
                <th className="py-2.5 px-4 font-semibold">Observed Value</th>
                <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {events.map((evt) => (
                <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-2.5 px-4 text-slate-400 font-bold">{evt.id}</td>
                  <td className="py-2.5 px-4 font-bold text-slate-100">{evt.event_type}</td>
                  <td className="py-2.5 px-4 text-cyan-400">{evt.protocol}</td>
                  <td className="py-2.5 px-4 text-emerald-400">
                    {evt.upgrade_status || "—"}
                  </td>
                  <td className="py-2.5 px-4 text-slate-300">
                    {formatFrameNumbers(evt.frame_numbers)}
                  </td>
                  <td className="py-2.5 px-4 text-slate-300 max-w-xs truncate">
                    {evt.observed_value || "—"}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={() => setSelectedEvent(evt)}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-[11px] font-mono transition-colors inline-flex items-center gap-1"
                    >
                      <Eye className="w-3 h-3 text-cyan-400" /> View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Security Event Detail Modal */}
      <SecurityEventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
};
