import React from 'react';
import { Database, ShieldAlert, Activity } from 'lucide-react';

interface EmptyStateProps {
  title?: string;
  message?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = "No Telemetry Available",
  message = "No operational events or security alerts have been recorded in the database yet."
}) => {
  return (
    <div className="glass-panel p-12 text-center flex flex-col items-center justify-center space-y-3 font-mono border-dashed border-slate-800">
      <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-500">
        <Database className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-bold text-slate-200">{title}</h3>
      <p className="text-xs text-slate-500 max-w-sm leading-relaxed">{message}</p>
    </div>
  );
};
