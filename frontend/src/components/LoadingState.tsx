import React from 'react';
import { RefreshCw } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({ message = "Querying SOC Telemetry Engine..." }) => {
  return (
    <div className="glass-panel p-12 text-center flex flex-col items-center justify-center space-y-3 font-mono">
      <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      <span className="text-xs text-slate-300 font-semibold">{message}</span>
    </div>
  );
};
