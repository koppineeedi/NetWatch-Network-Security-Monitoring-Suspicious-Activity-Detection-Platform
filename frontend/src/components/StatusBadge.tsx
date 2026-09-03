import React from 'react';

interface StatusBadgeProps {
  status: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const getStyle = () => {
    switch (status?.toUpperCase()) {
      case 'NEW':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse';
      case 'INVESTIGATING':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'SUSPICIOUS':
      case 'FLAGGED':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'RESOLVED':
      case 'CLOSED':
      case 'NORMAL':
      case 'HEALTHY':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded border ${getStyle()}`}>
      {status}
    </span>
  );
};
