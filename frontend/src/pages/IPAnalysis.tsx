import React, { useState } from 'react';
import { Search, Globe, ShieldAlert, Activity, Wifi, Clock, Server } from 'lucide-react';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

export const IPAnalysis: React.FC = () => {
  const [ipInput, setIpInput] = useState<string>('');
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [searched, setSearched] = useState<boolean>(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipInput.trim()) return;

    setLoading(true);
    setError(null);
    setSearched(true);

    try {
      const res = await apiService.getIPAnalysis(ipInput.trim());
      setData(res);
    } catch (err: any) {
      setError(err.message || "Failed to analyze IP address");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          <span>Host IP Address Security Telemetry Inspector</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Authoritative Host Observation Audit Based on Real Backend Database Records
        </p>
      </div>

      {/* Search Bar */}
      <div className="glass-panel p-5">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Enter IP Address (e.g. 192.168.1.55 or 127.0.0.1)..."
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            disabled={!ipInput.trim() || loading}
            className="px-6 py-2.5 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition font-bold disabled:opacity-50"
          >
            Audit IP Telemetry
          </button>
        </form>
      </div>

      {/* Audit Results */}
      {loading ? (
        <LoadingState message={`Auditing telemetry records for ${ipInput}...`} />
      ) : error ? (
        <ErrorState message={error} onRetry={() => handleSearch(new Event('submit') as any)} />
      ) : searched && (!data || data.total_events === 0) ? (
        <EmptyState title="No telemetry found for this IP." message="No network socket observations or uploaded logs match the queried IP address." />
      ) : data ? (
        <div className="space-y-6">
          {/* Top Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 glass-panel border-cyan-500/30 space-y-1">
              <span className="text-slate-500 text-[10px]">TOTAL EVENTS</span>
              <div className="text-xl font-bold text-cyan-400">{data.total_events}</div>
              <span className="text-[10px] text-slate-500">Observed Sessions</span>
            </div>
            <div className="p-4 glass-panel border-emerald-500/30 space-y-1">
              <span className="text-slate-500 text-[10px]">TOTAL ALERTS</span>
              <div className="text-xl font-bold text-emerald-400">{data.total_alerts}</div>
              <span className="text-[10px] text-slate-500">Triage Queue Records</span>
            </div>
            <div className="p-4 glass-panel border-amber-500/30 space-y-1">
              <span className="text-slate-500 text-[10px]">RULE DETECTIONS</span>
              <div className="text-xl font-bold text-amber-400">{data.total_detections}</div>
              <span className="text-[10px] text-slate-500">Backend Evaluations</span>
            </div>
            <div className="p-4 glass-panel border-slate-700 space-y-1">
              <span className="text-slate-500 text-[10px]">UNIQUE PORTS HIT</span>
              <div className="text-xl font-bold text-slate-200">{data.observed_ports.length}</div>
              <span className="text-[10px] text-slate-500">Ports: {data.observed_ports.join(', ') || 'None'}</span>
            </div>
          </div>

          {/* Detailed IP Audit Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass-panel p-5 space-y-4">
              <h3 className="text-sm font-bold text-slate-100">Host Observation Timeline</h3>
              <div className="space-y-2">
                <div className="p-3 bg-slate-950 rounded border border-slate-800 flex justify-between">
                  <span className="text-slate-500">First Observed Timestamp:</span>
                  <span className="text-slate-200 font-bold">{data.first_seen ? new Date(data.first_seen).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="p-3 bg-slate-950 rounded border border-slate-800 flex justify-between">
                  <span className="text-slate-500">Last Observed Timestamp:</span>
                  <span className="text-slate-200 font-bold">{data.last_seen ? new Date(data.last_seen).toLocaleString() : 'N/A'}</span>
                </div>
                <div className="p-3 bg-slate-950 rounded border border-slate-800 flex justify-between">
                  <span className="text-slate-500">Observed Protocols:</span>
                  <span className="text-cyan-300 font-bold">{data.observed_protocols.join(', ') || 'N/A'}</span>
                </div>
              </div>
            </div>

            <div className="glass-panel p-5 space-y-4">
              <h3 className="text-sm font-bold text-slate-100">Recent Observed Events Stream</h3>
              <div className="space-y-1.5 max-h-56 overflow-y-auto">
                {data.events.map((evt: any) => (
                  <div key={evt.id} className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] flex justify-between">
                    <span className="text-cyan-400 font-bold">{evt.source_ip} &rarr; {evt.dest_ip}:{evt.dest_port}</span>
                    <span className="text-slate-500">[{evt.protocol}] State: {evt.connection_state}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
};
