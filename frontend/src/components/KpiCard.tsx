import React from 'react';
import { LucideIcon } from 'lucide-react';

interface KpiCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: string;
  color?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'purple';
}

export const KpiCard: React.FC<KpiCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  color = 'cyan'
}) => {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/20',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      glow: 'hover:shadow-glow-cyan',
      text: 'text-cyan-400'
    },
    emerald: {
      border: 'border-emerald-500/20',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      glow: 'hover:shadow-glow-success',
      text: 'text-emerald-400'
    },
    amber: {
      border: 'border-amber-500/20',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      glow: 'hover:shadow-[0_0_20px_rgba(255,184,0,0.2)]',
      text: 'text-amber-400'
    },
    rose: {
      border: 'border-rose-500/20',
      iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      glow: 'hover:shadow-glow-danger',
      text: 'text-rose-400'
    },
    purple: {
      border: 'border-purple-500/20',
      iconBg: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      glow: 'hover:shadow-[0_0_20px_rgba(168,85,247,0.2)]',
      text: 'text-purple-400'
    }
  };

  const currentTheme = colorMap[color];

  return (
    <div className={`glass-panel p-5 border ${currentTheme.border} ${currentTheme.glow} transition-all duration-200`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono uppercase tracking-wider text-slate-400">{title}</span>
        <div className={`w-9 h-9 rounded-lg border flex items-center justify-center ${currentTheme.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="mt-3 flex items-baseline justify-between">
        <div className="text-2xl font-bold font-mono text-slate-100">{value}</div>
        {trend && <span className="text-xs font-mono text-slate-400">{trend}</span>}
      </div>
      {subtitle && <p className="text-[11px] text-slate-500 mt-1 font-mono">{subtitle}</p>}
    </div>
  );
};
