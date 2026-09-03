import React from 'react';
import { SecurityAlert } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';

interface AlertTableProps {
  alerts: SecurityAlert[];
}

export const AlertTable: React.FC<AlertTableProps> = ({ alerts }) => {
  return (
    <div className="space-y-3 font-mono text-xs">
      {alerts.map((alert) => (
        <div key={alert.id} className="glass-panel p-4 space-y-2 border-slate-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <SeverityBadge severity={alert.severity} />
              <span className="text-sm font-bold text-slate-100">{alert.detection_type}</span>
            </div>
            <StatusBadge status={alert.status} />
          </div>
          <p className="text-xs text-slate-300">{alert.description}</p>
          <div className="text-[10px] text-slate-500">
            Source: <span className="text-cyan-400">{alert.source_ip}</span> &rarr; Target: <span className="text-indigo-400">{alert.dest_ip}</span>
          </div>
        </div>
      ))}
    </div>
  );
};
