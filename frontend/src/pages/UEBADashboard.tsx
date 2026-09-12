import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, Zap, RefreshCw, BarChart2, Layers, AlertTriangle, CheckCircle, Search } from 'lucide-react';
import { UEBAStatus, AnalyticsStats, Anomaly } from '../types';
import { apiService } from '../services/apiService';
import { KpiCard } from '../components/KpiCard';
import { LoadingState } from '../components/LoadingState';
import { ErrorState } from '../components/ErrorState';

export const UEBADashboard: React.FC = () => {
  const [status, setStatus] = useState<UEBAStatus | null>(null);
  const [stats, setStats] = useState<AnalyticsStats | null>(null);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [runningCycle, setRunningCycle] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statusRes, statsRes, anomaliesRes] = await Promise.all([
        apiService.getUEBAStatus(),
        apiService.getAnalyticsStats(),
        apiService.getAnomalies(undefined, undefined, undefined, 20)
      ]);
      setStatus(statusRes);
      setStats(statsRes);
      setAnomalies(anomaliesRes);
    } catch (err: any) {
      setError(err.message || "Failed to load UEBA and Behavioral Analytics data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleTriggerCycle = async () => {
    setRunningCycle(true);
    try {
      await apiService.triggerAnalyticsCycle();
      await fetchData();
    } catch (err: any) {
      alert(`Analytics Cycle Trigger Error: ${err.message}`);
    } finally {
      setRunningCycle(false);
    }
  };

  if (loading) return <LoadingState message="Connecting to UEBA & Behavioral Engine..." />;
  if (error) return <ErrorState message={error} onRetry={fetchData} />;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>UEBA & Behavioral Analytics Dashboard</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Statistical 168-Hour Baselining, Non-Parametric Z-Score Anomaly Detection & Temporal Decay
          </p>
        </div>
        <button
          onClick={handleTriggerCycle}
          disabled={runningCycle}
          className="px-3.5 py-2 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-2 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${runningCycle ? 'animate-spin' : ''}`} />
          <span>{runningCycle ? 'Calculating Baselines...' : 'Run Analytics Cycle'}</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Monitored Entities"
          value={stats?.total_entities ?? 0}
          subtitle="IPs, Hosts & Accounts Tracked"
          icon={Layers}
          color="cyan"
        />
        <KpiCard
          title="Active 168h Baselines"
          value={stats?.baseline_status_breakdown.ACTIVE ?? 0}
          subtitle="Entities >= 20 Min Events"
          icon={CheckCircle}
          color="emerald"
        />
        <KpiCard
          title="Statistical Anomalies"
          value={stats?.total_anomalies ?? 0}
          subtitle="95th Percentile Deviations"
          icon={AlertTriangle}
          color="amber"
        />
        <KpiCard
          title="Active Attack Campaigns"
          value={stats?.active_campaigns ?? 0}
          subtitle="Clustered CMP-2026 Hits"
          icon={Zap}
          color="rose"
        />
      </div>

      {/* UEBA Subsystem Engine Status & Baseline Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-panel p-5 space-y-4 lg:col-span-1">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-2">
            <BarChart2 className="w-4 h-4 text-cyan-400" />
            <span>UEBA Engine Parameters</span>
          </h3>

          <div className="space-y-3 font-mono">
            <div className="flex justify-between items-center p-2 rounded bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400">Baseline Window</span>
              <span className="text-slate-200 font-bold">{status?.baseline_window_hours} Hours (7 Days)</span>
            </div>

            <div className="flex justify-between items-center p-2 rounded bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400">Min Samples Threshold</span>
              <span className="text-cyan-400 font-bold">{status?.min_events_threshold} Events</span>
            </div>

            <div className="flex justify-between items-center p-2 rounded bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400">Risk Temporal Decay</span>
              <span className="text-emerald-400 font-bold">{status?.risk_decay_hours} Hours Half-Life</span>
            </div>

            <div className="flex justify-between items-center p-2 rounded bg-slate-950/80 border border-slate-800">
              <span className="text-slate-400">Insufficient Data Entities</span>
              <span className="text-amber-400 font-bold">{status?.insufficient_data_entities_count} Entities</span>
            </div>
          </div>
        </div>

        {/* Baseline Status Breakdown */}
        <div className="glass-panel p-5 space-y-4 lg:col-span-2">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <span>Baseline Status Breakdown (Zero Synthetic Data Contract)</span>
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
            <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-center space-y-1">
              <span className="text-[10px] text-emerald-400 font-bold uppercase block">ACTIVE BASELINES</span>
              <span className="text-2xl font-bold text-slate-100">{stats?.baseline_status_breakdown.ACTIVE ?? 0}</span>
              <p className="text-[10px] text-slate-400">Statistical bounds active</p>
            </div>

            <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 text-center space-y-1">
              <span className="text-[10px] text-amber-400 font-bold uppercase block">INSUFFICIENT DATA</span>
              <span className="text-2xl font-bold text-slate-100">{stats?.baseline_status_breakdown.INSUFFICIENT_DATA ?? 0}</span>
              <p className="text-[10px] text-slate-400">Under 20 telemetry events</p>
            </div>

            <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-700 text-center space-y-1">
              <span className="text-[10px] text-slate-400 font-bold uppercase block">STALE BASELINES</span>
              <span className="text-2xl font-bold text-slate-100">{stats?.baseline_status_breakdown.STALE ?? 0}</span>
              <p className="text-[10px] text-slate-400">Inactive for &gt; 168 hours</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Statistical Anomalies Table */}
      <div className="glass-panel p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 font-mono">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <span>Recent Detected Statistical Anomalies</span>
          </h3>
          <span className="text-[10px] text-slate-400">Showing top {anomalies.length} recent anomalies</span>
        </div>

        {anomalies.length === 0 ? (
          <div className="text-slate-500 text-center py-8 border border-dashed border-slate-800 rounded font-mono">
            No statistical anomalies detected. Run telemetry collector to build historical baselines.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                  <th className="py-2 px-3">Entity ID</th>
                  <th className="py-2 px-3">Feature</th>
                  <th className="py-2 px-3">Observed</th>
                  <th className="py-2 px-3">Baseline Mean</th>
                  <th className="py-2 px-3">Score</th>
                  <th className="py-2 px-3">Severity</th>
                  <th className="py-2 px-3">MITRE</th>
                  <th className="py-2 px-3">Explanation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {anomalies.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-900/50 transition">
                    <td className="py-2.5 px-3 font-bold text-cyan-400">{a.entity_id}</td>
                    <td className="py-2.5 px-3 text-slate-300 font-semibold">{a.feature}</td>
                    <td className="py-2.5 px-3 text-rose-400 font-bold">{a.observed_value.toFixed(2)}</td>
                    <td className="py-2.5 px-3 text-slate-400">{a.baseline_value.toFixed(2)}</td>
                    <td className="py-2.5 px-3 font-bold text-amber-400">{a.anomaly_score.toFixed(1)}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                        a.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                        a.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                        'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      }`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[10px]">{a.mitre_technique || 'T1046'}</td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate" title={a.explanation}>{a.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
