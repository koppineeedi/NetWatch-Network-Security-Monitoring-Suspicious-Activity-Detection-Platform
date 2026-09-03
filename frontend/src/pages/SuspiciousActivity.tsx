import React, { useState } from 'react';
import { AlertTriangle, BookOpen, ExternalLink, ShieldAlert, Cpu, ArrowUpRight } from 'lucide-react';
import { NetworkEvent } from '../types';
import { MitreModal } from '../components/MitreModal';

interface SuspiciousActivityProps {
  events: NetworkEvent[];
}

export const SuspiciousActivity: React.FC<SuspiciousActivityProps> = ({ events }) => {
  const [isMitreOpen, setIsMitreOpen] = useState(false);
  const [selectedTactic, setSelectedTactic] = useState<string | undefined>(undefined);

  const suspiciousEvents = events.filter(e => e.status === 'SUSPICIOUS' || e.status === 'FLAGGED' || e.risk_score > 40);

  const mitreCards = [
    {
      tacticId: 'TA0043',
      name: 'Reconnaissance',
      technique: 'T1046 Network Service Discovery',
      severity: 'HIGH',
      description: 'Host probing active ports across subnet (Port Scan Detection rule active).'
    },
    {
      tacticId: 'TA0006',
      name: 'Credential Access',
      technique: 'T1110 Brute Force',
      severity: 'CRITICAL',
      description: 'Repeated failed authentication attempts against SSH port 22 and RDP port 3389.'
    },
    {
      tacticId: 'TA0010',
      name: 'Exfiltration',
      technique: 'T1041 Exfiltration Over C2 Channel',
      severity: 'HIGH',
      description: 'Outbound data payload transfer exceeding 10MB baseline volume.'
    },
    {
      tacticId: 'TA0011',
      name: 'Command and Control',
      technique: 'T1071 Application Layer Protocol',
      severity: 'MEDIUM',
      description: 'DNS query TXT payload size anomaly indicating potential tunneling.'
    }
  ];

  const handleOpenMitre = (tacticName?: string) => {
    setSelectedTactic(tacticName);
    setIsMitreOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 glass-panel border-cyan-500/30">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>Suspicious Network Activity & Anomaly Desk</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Flagged Heuristic Anomalies & MITRE ATT&CK® Enterprise Tactic Mapping
          </p>
        </div>
        <button
          onClick={() => handleOpenMitre()}
          className="px-3.5 py-2 text-xs font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition flex items-center space-x-2 shadow-glow-cyan"
        >
          <BookOpen className="w-4 h-4" />
          <span>Explore MITRE ATT&CK Framework</span>
        </button>
      </div>

      {/* MITRE ATT&CK Tactic Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {mitreCards.map((card) => (
          <div
            key={card.tacticId}
            onClick={() => handleOpenMitre(card.name)}
            className="glass-panel p-4 space-y-3 cursor-pointer hover:border-cyan-500/40 transition group"
          >
            <div className="flex items-center justify-between">
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/40">
                {card.tacticId}
              </span>
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                card.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                card.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                'bg-slate-700 text-slate-300'
              }`}>
                {card.severity}
              </span>
            </div>

            <div>
              <h3 className="text-sm font-bold text-slate-100 group-hover:text-cyan-400 transition flex items-center justify-between">
                <span>{card.name}</span>
                <ArrowUpRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition" />
              </h3>
              <p className="text-[11px] font-mono text-cyan-400/80 mt-0.5">{card.technique}</p>
            </div>

            <p className="text-xs text-slate-400 leading-normal">{card.description}</p>
          </div>
        ))}
      </div>

      {/* Flagged Anomalies Grid */}
      <div className="glass-panel p-5 space-y-4">
        <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center justify-between">
          <span>Flagged Network Anomaly Stream</span>
          <span className="text-xs font-normal text-slate-400">Total Flagged: {suspiciousEvents.length}</span>
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 font-mono text-[11px] text-slate-400 uppercase">
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Origin IP</th>
                <th className="py-2.5 px-3">Target IP:Port</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Payload Summary</th>
                <th className="py-2.5 px-3">Risk Rating</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 font-mono text-xs text-slate-300">
              {suspiciousEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-slate-900/60 transition">
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 text-rose-400 font-semibold">{evt.source_ip}</td>
                  <td className="py-2.5 px-3 text-indigo-300">{evt.dest_ip}:{evt.dest_port}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 text-[10px] font-bold bg-slate-800 text-cyan-300 rounded">
                      {evt.protocol}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate text-[11px]">
                    {evt.payload_summary || 'Suspicious burst threshold exceeded'}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                      {evt.risk_score.toFixed(0)} / 100
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* MITRE Knowledge Base Modal */}
      <MitreModal
        isOpen={isMitreOpen}
        onClose={() => setIsMitreOpen(false)}
        selectedTactic={selectedTactic}
      />
    </div>
  );
};
