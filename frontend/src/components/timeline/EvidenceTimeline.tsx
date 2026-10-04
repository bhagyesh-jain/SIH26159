import React, { useEffect, useRef } from "react";
import { Clock, AlertCircle } from "lucide-react";
import { EventResponse } from "../../types/api";
import { formatTimestamp } from "../../utils/formatting";

interface EvidenceTimelineProps {
  events: EventResponse[];
  highlightedFrameNumber?: number | null;
  onSelectFrame?: (frameNumber: number) => void;
}

export const EvidenceTimeline: React.FC<EvidenceTimelineProps> = ({
  events,
  highlightedFrameNumber,
  onSelectFrame,
}) => {
  const frameRefs = useRef<Record<number, HTMLDivElement | null>>({});

  useEffect(() => {
    if (highlightedFrameNumber && frameRefs.current[highlightedFrameNumber]) {
      const el = frameRefs.current[highlightedFrameNumber];
      if (el && typeof el.scrollIntoView === "function") {
        el.scrollIntoView({
          behavior: "smooth",
          block: "center",
        });
      }
    }
  }, [highlightedFrameNumber]);

  if (!events || events.length === 0) {
    return (
      <div className="p-8 bg-slate-900/40 border border-slate-800 rounded-lg text-center text-slate-500 font-mono text-xs">
        No packet events extracted for this session stream.
      </div>
    );
  }

  const isHighlightedFramePresent = highlightedFrameNumber
    ? events.some((e) => e.packet_number === highlightedFrameNumber)
    : true;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 font-sans">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <h3 className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" /> Evidence Packet Timeline ({events.length} Events)
        </h3>
        <span className="text-[11px] font-mono text-slate-500">
          Chronological reassembled frame order
        </span>
      </div>

      {highlightedFrameNumber && !isHighlightedFramePresent && (
        <div className="mb-4 p-3 bg-amber-950/60 border border-amber-800 text-amber-300 rounded font-mono text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>
            Evidence frame #{highlightedFrameNumber} is referenced by finding, but frame #{highlightedFrameNumber} is unavailable in this reassembled stream.
          </span>
        </div>
      )}

      <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {events.map((evt) => {
          const isHighlighted = highlightedFrameNumber === evt.packet_number;
          const obsData = evt.observed_json;
          let obsText = "";
          if (typeof obsData === "string") {
            obsText = obsData;
          } else if (obsData && typeof obsData === "object") {
            obsText = JSON.stringify(obsData);
          }

          return (
            <div
              key={evt.id || evt.packet_number}
              ref={(el) => {
                if (evt.packet_number) {
                  frameRefs.current[evt.packet_number] = el;
                }
              }}
              onClick={() => onSelectFrame && onSelectFrame(evt.packet_number)}
              className={`relative p-4 rounded-lg border transition-all cursor-pointer ${
                isHighlighted
                  ? "bg-cyan-950/40 border-cyan-500 shadow-lg shadow-cyan-950/50 ring-1 ring-cyan-500"
                  : "bg-slate-950/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-950/80"
              }`}
            >
              {/* Timeline Bullet Marker */}
              <div
                className={`absolute -left-[27px] top-4 w-3.5 h-3.5 rounded-full border-2 transition-colors ${
                  isHighlighted
                    ? "bg-cyan-400 border-cyan-200"
                    : "bg-slate-900 border-slate-600"
                }`}
              />

              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-2 mb-2 font-mono text-xs">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                      isHighlighted
                        ? "bg-cyan-500 text-slate-950"
                        : "bg-slate-800 text-cyan-400 border border-slate-700"
                    }`}
                  >
                    Frame #{evt.packet_number}
                  </span>
                  <span className="font-semibold text-slate-200">
                    {evt.event_type}
                  </span>
                </div>

                <div className="text-[11px] text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-slate-600" />
                  {formatTimestamp(evt.timestamp)}
                </div>
              </div>

              {/* Event Content / Payload */}
              <div className="font-mono text-xs text-slate-300 break-all bg-slate-900/60 p-2.5 rounded border border-slate-800/60">
                {obsText || "—"}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
