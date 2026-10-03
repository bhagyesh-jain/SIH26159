import React from "react";
import { AlertTriangle } from "lucide-react";

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = "API Communication Error",
  message,
  onRetry,
}) => {
  return (
    <div className="p-6 bg-red-950/30 border border-red-800/60 rounded-lg text-red-300">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
        <div className="flex-1">
          <h3 className="text-base font-semibold font-mono text-red-200">{title}</h3>
          <p className="text-sm mt-1 text-red-300/90">{message}</p>
          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-3 px-3 py-1.5 bg-red-900/60 hover:bg-red-800/60 border border-red-700 text-xs font-mono font-medium rounded text-red-100 transition-colors"
            >
              Retry Action
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
