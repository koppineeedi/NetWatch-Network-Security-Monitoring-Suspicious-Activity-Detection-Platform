import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Database, RefreshCw, CheckCircle, AlertTriangle, Activity, Search } from 'lucide-react';
import { ThreatIntelStats, IPReputation } from '../types';
import { apiService } from '../services/apiService';
import { KpiCard } from '../components/KpiCard';
import { LoadingState } from '../components/LoadingState';
import { ErrorState } from '../components/ErrorState';

export const ThreatIntelDashboard: React.FC = () => {
  const [stats, setStats] = useState<ThreatIntelStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchIp, setSearchIp] = useState<string>('');
  const [ipRepResult, setIpRepResult] = useState<IPReputation | null>(null);
  const [searchingIp, setSearchingIp] = useState<boolean>(false);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getThreatIntelStatus();
      setStats(data);
    } catch (err: any) {
      setError(err.message || "Failed to load threat intelligence status");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleIpLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchIp) return;
    setSearchingIp(true);
    try {
      const res = await apiService.getIPReputation(searchIp.strip ? searchIp.strip() : searchIp.trim());
      setIpRepResult(res);
    } catch (err: any) {
      alert(`IP Reputation Lookup Error: ${err.message}`);
    } finally {
      setSearchingIp(false);
    }
  };

  if (loading) return <LoadingState message="Connecting to Threat Intelligence Engine..." />;
  if (error) return <ErrorState message={error} onRetry={fetchStats} />;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Shield className="w-5 h-5 text-indigo-400" />
            <span>Threat Intelligence Overview</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            AbuseIPDB, AlienVault OTX, MISP Feed Aggregation & Live IOC Matching
          </p>
        </div>
        <button
          onClick={fetchStats}
          className="px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Intelligence</span>
        </button>
      </div>

      {/* 4 Threat Intel KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total IOC Records"
          value={stats?.total_iocs ?? 0}
          subtitle="Database Stored IOCs"
          icon={Database}
          color="cyan"
        />
        <KpiCard
          title="Active IOCs"
          value={stats?.active_iocs ?? 0}
          subtitle="Non-Expired Indicators"
          icon={CheckCircle}
          color="emerald"
        />
        <KpiCard
          title="IOC Telemetry Matches"
          value={stats?.recent_matches_count ?? 0}
          subtitle="Real Ingested Telemetry Hits"
          icon={ShieldAlert}
          color="rose"
        />
        <KpiCard
          title="High-Confidence IOCs"
          value={stats?.high_confidence_matches_count ?? 0}
          subtitle="Confidence Score >= 80"
          icon={AlertTriangle}
          color="amber"
        />
      </div>

      {/* Quick IP Reputation Inspector Form */}
      <div className="glass-panel p-5 space-y-4">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <Search className="w-4 h-4 text-cyan-400" />
          <span>Quick IP Reputation & Threat Lookup</span>
        </h3>

        <form onSubmit={handleIpLookup} className="flex gap-3">
          <input
            type="text"
            placeholder="Enter target IP address (e.g. 8.8.8.8, 192.168.1.100)..."
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            type="submit"
            disabled={searchingIp}
            className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-lg transition disabled:opacity-50"
          >
            {searchingIp ? 'Searching...' : 'Lookup IP'}
          </button>
        </form>

        {ipRepResult && (
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-200 font-bold text-sm">Analysis for {ipRepResult.ip_address}</span>
              <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                ipRepResult.status === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
              }`}>
                PROVIDER: {ipRepResult.provider.toUpperCase()} ({ipRepResult.status})
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
              <div>
                <span className="text-slate-500 text-[10px] block">REPUTATION SCORE</span>
                <span className="text-emerald-400 font-bold text-sm">{ipRepResult.reputation_score.toFixed(1)}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">ABUSE CONFIDENCE</span>
                <span className="text-amber-400 font-bold text-sm">{ipRepResult.abuse_confidence}%</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">COUNTRY / ASN</span>
                <span className="text-slate-200">{ipRepResult.country || 'N/A'} ({ipRepResult.asn || 'N/A'})</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">ORGANIZATION</span>
                <span className="text-slate-300">{ipRepResult.organization || 'N/A'}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Provider Status & Recent IOC Matches Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Intel Providers */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 font-mono">Integrated Threat Intelligence Providers</h3>

          <div className="space-y-3">
            {stats?.providers.map((p) => (
              <div key={p.provider_name} className="p-3 rounded bg-slate-950/80 border border-slate-800 flex items-center justify-between font-mono">
                <div>
                  <h4 className="text-slate-200 font-bold">{p.display_name}</h4>
                  <p className="text-[10px] text-slate-500">IOCs Ingested: <span className="text-cyan-400">{p.ioc_count}</span></p>
                </div>
                <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                  p.status === 'CONNECTED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                  p.status === 'CONFIGURED' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' :
                  'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                }`}>
                  {p.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent IOC Matches */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 font-mono">Recent Telemetry IOC Matches</h3>

          {!stats?.recent_matches || stats.recent_matches.length === 0 ? (
            <div className="text-slate-500 text-center py-6 border border-dashed border-slate-800 rounded font-mono">
              No telemetry IOC matches detected.
            </div>
          ) : (
            <div className="space-y-2 font-mono">
              {stats.recent_matches.map((m) => (
                <div key={m.id} className="p-3 rounded bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-rose-400 font-bold">{m.ioc_type}: {m.ioc_value}</span>
                    <p className="text-[10px] text-slate-500">Field: {m.matched_field} | Provider: {m.provider}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    Confidence {m.confidence}%
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
