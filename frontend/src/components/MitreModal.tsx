import React from 'react';
import { X, ShieldAlert, BookOpen, CheckCircle, ExternalLink } from 'lucide-react';

interface MitreModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedTactic?: string;
}

export const MitreModal: React.FC<MitreModalProps> = ({ isOpen, onClose, selectedTactic }) => {
  if (!isOpen) return null;

  const tacticsDetails = [
    {
      id: 'TA0043',
      name: 'Reconnaissance',
      techniques: ['T1046 - Network Service Discovery', 'T1595 - Active Scanning'],
      description: 'Adversaries gather information that can be used to plan future operations. In NetWatch, port scanning and IP probing trigger Reconnaissance alerts.',
      mitigation: 'Implement firewall port blocking, deploy honeypots, rate-limit SYN packets, and monitor anomalous ICMP/UDP probes.',
      detectRules: 'R-SCAN-01 (Port Scanning Reconnaissance)'
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: ['T1110 - Brute Force', 'T1078 - Valid Accounts'],
      description: 'Adversaries attempt to steal credentials like account usernames and passwords. NetWatch flags rapid SSH and RDP authentication attempts.',
      mitigation: 'Enforce Multi-Factor Authentication (MFA), account lockout thresholds, strong password policies, and fail2ban rules.',
      detectRules: 'R-BRUTE-01 (SSH / RDP Credential Spraying)'
    },
    {
      id: 'TA0010',
      name: 'Exfiltration',
      techniques: ['T1041 - Exfiltration Over C2 Channel', 'T1048 - Exfiltration Over Alternative Protocol'],
      description: 'Adversaries steal sensitive data from your network. NetWatch monitors large outbound transfer bursts exceeding baseline network thresholds.',
      mitigation: 'Deploy Data Loss Prevention (DLP) filters, outbound bandwidth rate-limiting, egress firewall filtering, and encrypted inspection.',
      detectRules: 'R-EXFIL-01 (Large Outbound Data Exfiltration)'
    },
    {
      id: 'TA0011',
      name: 'Command and Control (C2)',
      techniques: ['T1071 - Application Layer Protocol', 'T1095 - Non-Application Layer Protocol'],
      description: 'Adversaries communicate with systems under their control within a victim network. NetWatch detects DNS tunneling and high ICMP payload anomalies.',
      mitigation: 'Use DNS Sinkholing, inspect DNS query length entropy, restrict unapproved outbound protocol ports, and use proxy inspection.',
      detectRules: 'R-ANOM-01 (DNS/ICMP Payload Anomaly)'
    }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-3xl max-h-[85vh] overflow-y-auto border-cyan-500/30 p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <BookOpen className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100">MITRE ATT&CK® Defensive Framework Guide</h2>
              <p className="text-xs text-slate-400 font-mono">Educational SOC Knowledge Base & Mapping</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          {tacticsDetails.map((tactic) => (
            <div
              key={tactic.id}
              className={`p-4 rounded-lg border transition ${
                selectedTactic === tactic.name
                  ? 'bg-cyan-950/30 border-cyan-500/50 shadow-glow-cyan'
                  : 'bg-slate-900/50 border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/40">
                    {tactic.id}
                  </span>
                  <h3 className="text-sm font-bold text-slate-100">{tactic.name}</h3>
                </div>
                <span className="text-[11px] font-mono text-slate-400">{tactic.detectRules}</span>
              </div>

              <p className="text-xs text-slate-300 mt-2 leading-relaxed">{tactic.description}</p>

              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
                  <span className="font-mono text-cyan-400 text-[11px] font-semibold block mb-1">Target Techniques:</span>
                  <ul className="list-disc list-inside text-slate-400 text-[11px] space-y-0.5">
                    {tactic.techniques.map((tech, i) => <li key={i}>{tech}</li>)}
                  </ul>
                </div>
                <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-800/30">
                  <span className="font-mono text-emerald-400 text-[11px] font-semibold block mb-1 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" /> Defensive Countermeasures:
                  </span>
                  <p className="text-slate-300 text-[11px] leading-normal">{tactic.mitigation}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition"
          >
            Close Knowledge Base
          </button>
        </div>
      </div>
    </div>
  );
};
