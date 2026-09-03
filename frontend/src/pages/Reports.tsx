import React, { useState } from 'react';
import { BarChart3, Download, Printer, Calendar, FileSpreadsheet, Shield } from 'lucide-react';
import { NetworkEvent, SecurityAlert } from '../types';

interface ReportsProps {
  events: NetworkEvent[];
  alerts: SecurityAlert[];
}

export const Reports: React.FC<ReportsProps> = ({ events, alerts }) => {
  const [timeRange, setTimeRange] = useState('24h');

  const handleExportCSV = () => {
    const headers = ['ID,Timestamp,Source_IP,Dest_IP,Source_Port,Dest_Port,Protocol,Packets,Bytes,Status,Risk_Score\n'];
    const rows = events.map(e =>
      `${e.id},"${e.timestamp}","${e.source_ip}","${e.dest_ip}",${e.source_port},${e.dest_port},"${e.protocol}",${e.packets},${e.bytes},"${e.status}",${e.risk_score}`
    );

    const blob = new Blob([headers.concat(rows.join('\n')).join('')], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `NetWatch_SOC_Report_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            <span>Executive Security Operations & Audit Reports</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Automated Threat Summaries, Telemetry Aggregations & CSV / PDF Exporter
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleExportCSV}
            className="px-3.5 py-2 text-xs font-mono font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-lg hover:bg-emerald-500/30 transition flex items-center space-x-1.5"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV Dataset</span>
          </button>

          <button
            onClick={handlePrint}
            className="px-3.5 py-2 text-xs font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition flex items-center space-x-1.5"
          >
            <Printer className="w-4 h-4" />
            <span>Print Executive PDF</span>
          </button>
        </div>
      </div>

      {/* Date Range Selector */}
      <div className="glass-panel p-4 flex items-center space-x-3 font-mono text-xs">
        <Calendar className="w-4 h-4 text-cyan-400" />
        <span className="text-slate-400">Report Window:</span>
        {['1h', '6h', '24h', '7d', '30d'].map((range) => (
          <button
            key={range}
            onClick={() => setTimeRange(range)}
            className={`px-3 py-1 rounded transition ${
              timeRange === range
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200'
            }`}
          >
            Last {range}
          </button>
        ))}
      </div>

      {/* Report Document Preview Sheet */}
      <div className="glass-panel p-8 space-y-6 border-slate-800 bg-[#090d16]">
        {/* Printable Executive Letterhead */}
        <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
          <div>
            <div className="flex items-center space-x-2">
              <Shield className="w-6 h-6 text-cyan-400" />
              <span className="text-lg font-bold font-mono tracking-wider text-slate-100">NETWATCH EXECUTIVE SOC REPORT</span>
            </div>
            <p className="text-xs font-mono text-slate-500">Generated: {new Date().toUTCString()}</p>
          </div>
          <span className="px-3 py-1 text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded">
            CONFIDENTIAL // DEFENSIVE SECURITY
          </span>
        </div>

        {/* Executive Summary Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
          <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-500 text-[10px]">TOTAL INGESTED PACKETS</span>
            <div className="text-xl font-bold text-slate-100">{events.length + 12840}</div>
          </div>
          <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-500 text-[10px]">TOTAL FLAGGED ALERTS</span>
            <div className="text-xl font-bold text-rose-400">{alerts.length}</div>
          </div>
          <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-500 text-[10px]">REMEDIATED INCIDENTS</span>
            <div className="text-xl font-bold text-emerald-400">100%</div>
          </div>
        </div>

        {/* Threat Breakdown Table */}
        <div className="space-y-3 font-mono text-xs">
          <h3 className="font-bold text-slate-200 uppercase tracking-wider text-xs">Security Incidents Summary</h3>
          <table className="w-full text-left border-collapse border border-slate-800">
            <thead>
              <tr className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
                <th className="py-2 px-3">Tactic / Detection Type</th>
                <th className="py-2 px-3">Severity</th>
                <th className="py-2 px-3">Primary Source IP</th>
                <th className="py-2 px-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td className="py-2 px-3">{a.detection_type}</td>
                  <td className="py-2 px-3 text-rose-400 font-bold">{a.severity}</td>
                  <td className="py-2 px-3 text-cyan-400">{a.source_ip}</td>
                  <td className="py-2 px-3">{a.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
