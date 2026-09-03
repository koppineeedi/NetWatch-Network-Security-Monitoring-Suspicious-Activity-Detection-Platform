import React, { useEffect, useState } from 'react';
import { Activity, ShieldAlert, Wifi, AlertTriangle, Play, Pause, Database, Clock, RefreshCw } from 'lucide-react';
import { KpiCard } from '../components/KpiCard';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { SocStatistics, SecurityAlert, NetworkEvent } from '../types';
import { apiService, TelemetryStatus } from '../services/apiService';
import { websocketService } from '../services/websocketService';

interface DashboardProps {
  onNavigate: (path: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<SocStatistics | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryStatus>({
    running: false,
    collector: "LOCAL_NETWORK",
    interval: 10,
    last_collection_time: null,
    events_collected: 0,
    events_stored: 0,
    errors: 0
  });
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState<boolean>(false);

  const fetchRealData = async () => {
    try {
      const [st, evts, alts, telStatus] = await Promise.all([
        apiService.getStatistics(),
        apiService.getEvents(),
        apiService.getAlerts(),
        apiService.getTelemetryStatus()
      ]);
      setStats(st);
      setEvents(evts);
      setAlerts(alts);
      setTelemetry(telStatus);
    } catch (err: any) {
      setError(err.message || "Failed to connect to backend REST API");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRealData();

    // Subscribe to WebSocket real-time event stream
    const unsubEvent = websocketService.subscribe('network_event', (evtData: any) => {
      if (!evtData || !evtData.id) return;
      setEvents((prev) => {
        if (prev.some((e) => e.id === evtData.id)) return prev;
        return [evtData as NetworkEvent, ...prev].slice(0, 50);
      });
      setStats((prev) => prev ? { ...prev, total_events: prev.total_events + 1 } : prev);
    });

    const unsubDetection = websocketService.subscribe('detection', () => {
      setStats((prev) => prev ? { ...prev, total_detections: (prev.total_detections || 0) + 1 } : prev);
    });

    const unsubAlert = websocketService.subscribe('alert', (alertData: any) => {
      if (!alertData || !alertData.id) return;
      setAlerts((prev) => {
        if (prev.some((a) => a.id === alertData.id)) return prev;
        return [alertData as SecurityAlert, ...prev].slice(0, 50);
      });
      setStats((prev) => prev ? { ...prev, open_alerts: prev.open_alerts + 1 } : prev);
    });

    const unsubStatus = websocketService.subscribe('telemetry_status', (statusData: any) => {
      if (statusData) setTelemetry(statusData as TelemetryStatus);
    });

    return () => {
      unsubEvent();
      unsubDetection();
      unsubAlert();
      unsubStatus();
    };
  }, []);

  const handleToggleCollector = async () => {
    setToggling(true);
    try {
      if (telemetry.running) {
        const res = await apiService.stopTelemetry();
        setTelemetry(res);
      } else {
        const res = await apiService.startTelemetry();
        setTelemetry(res);
      }
      await fetchRealData();
    } catch (err: any) {
      alert(`Telemetry control error: ${err.message}`);
    } finally {
      setToggling(false);
    }
  };

  if (loading) return <LoadingState message="Connecting to Real Telemetry Service..." />;
  if (error) return <ErrorState message={error} onRetry={fetchRealData} />;

  const hasData = (stats?.total_events ?? 0) > 0 || events.length > 0;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Top Telemetry Control Bar */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Local Network Security Telemetry</span>
            <span className={`text-xs px-2.5 py-0.5 rounded font-bold ${
              telemetry.running ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 animate-pulse' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
            }`}>
              {telemetry.running ? 'TELEMETRY RUNNING' : 'TELEMETRY STOPPED'}
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Collector: <span className="text-cyan-300 font-bold">{telemetry.collector}</span> | Interval: <span className="text-cyan-300 font-bold">{telemetry.interval}s</span> | Observed Collected: <span className="text-slate-200">{telemetry.events_collected}</span> | DB Stored: <span className="text-emerald-400 font-bold">{telemetry.events_stored}</span>
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchRealData}
            title="Refresh Data"
            className="p-2 rounded-lg bg-slate-900 text-slate-300 hover:text-cyan-400 border border-slate-800 transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleToggleCollector}
            disabled={toggling}
            className={`px-4 py-2 text-xs font-semibold rounded-lg flex items-center space-x-2 transition disabled:opacity-50 ${
              telemetry.running
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 hover:bg-rose-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 shadow-glow-success'
            }`}
          >
            {telemetry.running ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            <span>{telemetry.running ? 'Stop Telemetry Collection' : 'Start Telemetry Collection'}</span>
          </button>
        </div>
      </div>

      {/* 4 Real KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Events"
          value={stats?.total_events ?? 0}
          subtitle="Real Stored DB Events"
          icon={Activity}
          color="cyan"
        />
        <KpiCard
          title="Active Connections"
          value={stats?.active_connections ?? 0}
          subtitle="Observed Unique Local IPs"
          icon={Wifi}
          color="emerald"
        />
        <KpiCard
          title="Detections"
          value={stats?.total_detections ?? 0}
          subtitle="Rule Engine Evaluations"
          icon={AlertTriangle}
          color="amber"
        />
        <KpiCard
          title="Open Alerts"
          value={stats?.open_alerts ?? 0}
          subtitle="Active Triage Queue"
          icon={ShieldAlert}
          color="rose"
        />
      </div>

      {/* Main Content Area */}
      {!hasData ? (
        <EmptyState
          title="No live telemetry received."
          message="Click 'Start Telemetry Collection' above to begin observing active local machine network sockets passively via psutil."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Real Network Events */}
          <div className="glass-panel p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 font-mono">Recent Real Observed Events</h3>
              <button onClick={() => onNavigate('/events')} className="text-xs text-cyan-400 hover:underline">View All</button>
            </div>

            <div className="space-y-2">
              {events.slice(0, 5).map((evt) => (
                <div key={evt.id} className="p-3 rounded bg-slate-950/80 border border-slate-800 flex items-center justify-between font-mono">
                  <div>
                    <span className="text-cyan-400 font-bold">{evt.source_ip || '127.0.0.1'} &rarr; {evt.dest_ip || 'N/A'}:{evt.dest_port || 'N/A'}</span>
                    <p className="text-slate-500 text-[10px]">
                      {evt.process_name ? `Process: ${evt.process_name} | ` : ''}Protocol: {evt.protocol} | State: {evt.connection_state}
                    </p>
                  </div>
                  <span className="text-[10px] text-slate-400 px-2 py-0.5 bg-slate-900 border border-slate-800 rounded">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Telemetry Status Inspector Card */}
          <div className="glass-panel p-5 space-y-4 font-mono">
            <h3 className="text-sm font-bold text-slate-100">Local Telemetry Diagnostics</h3>

            <div className="space-y-2 text-xs">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-500">Collector Name:</span>
                <span className="text-cyan-300 font-bold">{telemetry.collector}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-500">Last Collection Cycle:</span>
                <span className="text-slate-200">{telemetry.last_collection_time ? new Date(telemetry.last_collection_time).toLocaleString() : 'N/A'}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-500">Events Collected / Stored:</span>
                <span className="text-emerald-400 font-bold">{telemetry.events_collected} / {telemetry.events_stored}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
                <span className="text-slate-500">Collector Error Count:</span>
                <span className="text-slate-200">{telemetry.errors}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
