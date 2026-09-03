import React, { useState, useEffect } from 'react';
import { Search, Filter, RefreshCw, Eye, Activity, Radio } from 'lucide-react';
import { NetworkEvent } from '../types';
import { apiService } from '../services/apiService';
import { websocketService } from '../services/websocketService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { PayloadInspectorModal } from '../components/PayloadInspectorModal';

export const NetworkEvents: React.FC = () => {
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [inspectEvent, setInspectEvent] = useState<NetworkEvent | null>(null);

  const loadEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getEvents(searchTerm, protocolFilter, statusFilter);
      setEvents(data);
    } catch (err: any) {
      setError(err.message || "Failed to load network events");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [searchTerm, protocolFilter, statusFilter]);

  // Real-time WebSocket subscription for live network events
  useEffect(() => {
    const unsubscribe = websocketService.subscribe('network_event', (liveEvt: any) => {
      if (!liveEvt || !liveEvt.id) return;
      setEvents((prevEvents) => {
        // Prevent duplicate events
        if (prevEvents.some((e) => e.id === liveEvt.id)) return prevEvents;
        // Prepend new live event to bounded buffer (max 200 items)
        return [liveEvt as NetworkEvent, ...prevEvents].slice(0, 200);
      });
    });

    return () => {
      unsubscribe();
    };
  }, []);

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 glass-panel border-cyan-500/30">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Network Events Telemetry Explorer</span>
            <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1">
              <Radio className="w-3 h-3 animate-pulse" />
              LIVE STREAM ACTIVE
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real Ingested Packet & Local Socket Session Stream Inspection Table
          </p>
        </div>
        <button
          onClick={loadEvents}
          className="px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Database Events</span>
        </button>
      </div>

      {/* Filter Controls Bar */}
      <div className="glass-panel p-4 flex flex-col md:flex-row items-center gap-4 justify-between">
        {/* Search */}
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP, Hostname, or Process..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          <div className="flex items-center space-x-2 text-slate-400">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Filters:</span>
          </div>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Protocols</option>
            <option value="HTTPS">HTTPS</option>
            <option value="HTTP">HTTP</option>
            <option value="TCP">TCP</option>
            <option value="DNS">DNS</option>
            <option value="UDP">UDP</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="NORMAL">Normal</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="FLAGGED">Flagged</option>
          </select>
        </div>
      </div>

      {/* Main Content */}
      {loading ? (
        <LoadingState message="Loading network events from database..." />
      ) : error ? (
        <ErrorState message={error} onRetry={loadEvents} />
      ) : events.length === 0 ? (
        <EmptyState
          title="No live telemetry received."
          message="Start Local Network Monitoring on the Dashboard to begin collecting authorized local socket observations."
        />
      ) : (
        <div className="glass-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Source Host / IP</th>
                  <th className="py-3 px-4">Target Host / IP</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Connection State</th>
                  <th className="py-3 px-4">Source Tag</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs text-slate-300">
                {events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-900/60 transition">
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-cyan-400 font-semibold">{evt.source_ip || '127.0.0.1'}</div>
                      <div className="text-[10px] text-slate-500">{evt.process_name || evt.hostname || `port:${evt.source_port}`}</div>
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
                    <td className="py-3 px-4 text-slate-300">
                      {evt.connection_state || 'ESTABLISHED'}
                    </td>
                    <td className="py-3 px-4 text-[10px] text-slate-400 font-mono">
                      {evt.source || 'LOCAL_NETWORK'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setInspectEvent(evt)}
                        className="px-2.5 py-1 text-[11px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded hover:bg-cyan-500/20 transition flex items-center space-x-1 ml-auto"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <PayloadInspectorModal event={inspectEvent} onClose={() => setInspectEvent(null)} />
    </div>
  );
};
