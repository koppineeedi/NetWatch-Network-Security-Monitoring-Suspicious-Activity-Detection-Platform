import React from 'react';
import { Network, ShieldAlert, Cpu, Server, Lock, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export const PortProtocolAnalysis: React.FC = () => {
  const topPortsData = [
    { port: '443 (HTTPS)', count: 5420, risk: 'LOW', description: 'Encrypted Web Traffic' },
    { port: '80 (HTTP)', count: 3210, risk: 'MEDIUM', description: 'Plaintext Web Traffic' },
    { port: '22 (SSH)', count: 1890, risk: 'HIGH', description: 'Secure Shell Remote Access (Brute-Force Target)' },
    { port: '53 (DNS)', count: 1250, risk: 'MEDIUM', description: 'Domain Name Resolution' },
    { port: '3389 (RDP)', count: 870, risk: 'HIGH', description: 'Windows Remote Desktop Protocol' },
    { port: '8080 (HTTP-Alt)', count: 640, risk: 'MEDIUM', description: 'Alternative Proxy/Web Service' },
  ];

  const protocolRiskData = [
    { protocol: 'HTTPS', volume: 55, riskScore: 15 },
    { protocol: 'HTTP', volume: 25, riskScore: 45 },
    { protocol: 'SSH', volume: 12, riskScore: 85 },
    { protocol: 'DNS', volume: 8, riskScore: 60 },
    { protocol: 'ICMP', volume: 3, riskScore: 70 },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <span>Port & Protocol Analytics Matrix</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Deep Packet Inspection & Port Targeting Distribution Analysis
        </p>
      </div>

      {/* Grid of Port Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {topPortsData.slice(0, 3).map((item) => (
          <div key={item.port} className="glass-panel p-5 space-y-3 border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-cyan-400">{item.port}</span>
              <span className={`px-2 py-0.5 text-[10px] font-bold font-mono rounded ${
                item.risk === 'HIGH' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                item.risk === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}>
                {item.risk} RISK
              </span>
            </div>
            <div className="text-2xl font-mono font-bold text-slate-100">{item.count.toLocaleString()} <span className="text-xs text-slate-500">connections</span></div>
            <p className="text-xs text-slate-400 font-mono">{item.description}</p>
          </div>
        ))}
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Targeted Ports Chart */}
        <div className="glass-panel p-5 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 font-mono">Targeted Port Connection Volume</h3>
            <p className="text-[11px] text-slate-400 font-mono">Connection count per destination port</p>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topPortsData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                <XAxis dataKey="port" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0e131f', borderColor: '#1e293b', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" fill="#00f0ff" radius={[4, 4, 0, 0]}>
                  {topPortsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.risk === 'HIGH' ? '#ff0055' : entry.risk === 'MEDIUM' ? '#ffb800' : '#00f0ff'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Risk Analyzer */}
        <div className="glass-panel p-5 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 font-mono">Protocol Risk Profile Analyzer</h3>
            <p className="text-[11px] text-slate-400 font-mono">Risk score vs traffic volume</p>
          </div>

          <div className="space-y-4 pt-2">
            {protocolRiskData.map((item) => (
              <div key={item.protocol} className="space-y-1.5 font-mono">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-200 font-bold">{item.protocol} Protocol</span>
                  <span className="text-slate-400">Risk Score: <span className="text-rose-400 font-bold">{item.riskScore}/100</span></span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-3 border border-slate-800 overflow-hidden flex">
                  <div
                    className="h-full bg-cyan-400"
                    style={{ width: `${item.volume}%` }}
                    title={`Traffic Volume: ${item.volume}%`}
                  ></div>
                  <div
                    className="h-full bg-rose-500"
                    style={{ width: `${item.riskScore / 2}%` }}
                    title={`Risk Index: ${item.riskScore}`}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
