import React from 'react';
import { X, Code, Shield, Terminal, Clock, HardDrive } from 'lucide-react';
import { NetworkEvent } from '../types';

interface PayloadInspectorModalProps {
  event: NetworkEvent | null;
  onClose: () => void;
}

export const PayloadInspectorModal: React.FC<PayloadInspectorModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-2xl border-cyan-500/30 p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 font-mono">Payload & Packet Inspector — Event #{event.id}</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">SOURCE HOST / IP</span>
            <span className="text-cyan-300 font-semibold">{event.source_ip}:{event.source_port}</span>
          </div>
          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">TARGET HOST / IP</span>
            <span className="text-indigo-300 font-semibold">{event.dest_ip}:{event.dest_port}</span>
          </div>
          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">PROTOCOL / STATUS</span>
            <span className="text-emerald-400 font-semibold">{event.protocol} / {event.status}</span>
          </div>
          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] text-slate-500 block">RISK SCORE</span>
            <span className={`font-semibold ${event.risk_score > 50 ? 'text-rose-400' : 'text-slate-300'}`}>
              {event.risk_score.toFixed(1)} / 100
            </span>
          </div>
        </div>

        {/* Raw Payload Inspection */}
        <div>
          <span className="text-xs font-mono text-slate-400 block mb-1">Payload Summary & Decoded Strings:</span>
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed max-h-48">
            <pre>{event.payload_summary || 'No application layer payload recorded (Raw TCP handshake)'}</pre>
          </div>
        </div>

        {/* Full JSON Structure */}
        <div>
          <span className="text-xs font-mono text-slate-400 block mb-1">Full Telemetry Record JSON:</span>
          <div className="p-3 rounded-lg bg-slate-950/90 border border-slate-800 font-mono text-[11px] text-cyan-400/90 overflow-x-auto max-h-40">
            <pre>{JSON.stringify(event, null, 2)}</pre>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
