import React from 'react';
import { NetworkEvent } from '../types';
import { StatusBadge } from './StatusBadge';
import { Eye } from 'lucide-react';

interface EventTableProps {
  events: NetworkEvent[];
  onInspect?: (event: NetworkEvent) => void;
}

export const EventTable: React.FC<EventTableProps> = ({ events, onInspect }) => {
  return (
    <div className="glass-panel overflow-hidden font-mono text-xs">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4">Source Host / IP</th>
              <th className="py-3 px-4">Target Host / IP</th>
              <th className="py-3 px-4">Protocol</th>
              <th className="py-3 px-4">Source Tag</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80 text-slate-300">
            {events.map((evt) => (
              <tr key={evt.id} className="hover:bg-slate-900/60 transition">
                <td className="py-3 px-4 text-slate-400 text-[11px]">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </td>
                <td className="py-3 px-4">
                  <div className="text-cyan-400 font-semibold">{evt.source_ip || '127.0.0.1'}</div>
                  <div className="text-[10px] text-slate-500">{evt.process_name || evt.source_host || `port:${evt.source_port}`}</div>
                </td>
                <td className="py-3 px-4">
                  <div className="text-indigo-300 font-semibold">{evt.dest_ip || 'N/A'}</div>
                  <div className="text-[10px] text-slate-500">Port {evt.dest_port || 'N/A'}</div>
                </td>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                    {evt.protocol || 'TCP'}
                  </span>
                </td>
                <td className="py-3 px-4 text-[10px] text-slate-400 font-mono">
                  {evt.collector || 'LOCAL_NETWORK'}
                </td>
                <td className="py-3 px-4">
                  <StatusBadge status={evt.status} />
                </td>
                <td className="py-3 px-4 text-right">
                  {onInspect && (
                    <button
                      onClick={() => onInspect(evt)}
                      className="px-2.5 py-1 text-[11px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded hover:bg-cyan-500/20 transition flex items-center space-x-1 ml-auto"
                    >
                      <Eye className="w-3 h-3" />
                      <span>Inspect</span>
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
