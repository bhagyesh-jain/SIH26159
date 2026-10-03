import React from "react";
import { Inbox } from "lucide-react";

interface EmptyStateProps {
  title?: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = "No Data Found",
  description = "No evidence or records are available for this view.",
  action,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 bg-slate-900/30 border border-slate-800 border-dashed rounded-lg text-center">
      <Inbox className="w-10 h-10 text-slate-600 mb-3" />
      <h3 className="text-base font-semibold font-mono text-slate-300">{title}</h3>
      <p className="text-sm text-slate-500 max-w-sm mt-1 mb-4">{description}</p>
      {action}
    </div>
  );
};
