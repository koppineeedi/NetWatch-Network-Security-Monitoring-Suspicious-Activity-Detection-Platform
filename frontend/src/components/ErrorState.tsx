import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  message?: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  message = "Failed to query backend REST API endpoint.",
  onRetry
}) => {
  return (
    <div className="glass-panel p-10 text-center flex flex-col items-center justify-center space-y-4 font-mono border-rose-500/30">
      <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
        <AlertCircle className="w-6 h-6" />
      </div>
      <div>
        <h3 className="text-sm font-bold text-slate-100">Telemetry Engine Error</h3>
        <p className="text-xs text-rose-300 mt-1">{message}</p>
      </div>

      {onRetry && (
        <button
          onClick={onRetry}
          className="px-4 py-2 bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded-lg hover:bg-rose-500/30 transition text-xs font-semibold flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry API Connection</span>
        </button>
      )}
    </div>
  );
};
