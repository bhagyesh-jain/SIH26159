import React from "react";
import { Loader2 } from "lucide-react";

interface LoadingStateProps {
  message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = "Loading forensic data...",
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 bg-slate-900/50 border border-slate-800 rounded-lg text-slate-400">
      <Loader2 className="w-8 h-8 animate-spin text-cyan-500 mb-3" />
      <p className="text-sm font-mono text-slate-300">{message}</p>
    </div>
  );
};
