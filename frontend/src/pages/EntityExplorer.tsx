import React, { useState, useEffect } from 'react';
import { Layers, ShieldAlert, Activity, Search, RefreshCw, BarChart2, TrendingUp, Users, AlertTriangle, CheckCircle, X } from 'lucide-react';
import { Entity, BehaviorBaseline, EntityRiskHistory, Anomaly } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { ErrorState } from '../components/ErrorState';

export const EntityExplorer: React.FC = () => {
  const [entities, setEntities] = useState<Entity[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [minRiskFilter, setMinRiskFilter] = useState<number | undefined>(undefined);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modal inspection state
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
  const [baselines, setBaselines] = useState<BehaviorBaseline[]>([]);
  const [riskHistory, setRiskHistory] = useState<EntityRiskHistory[]>([]);
  const [peerGroup, setPeerGroup] = useState<any>(null);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loadingModal, setLoadingModal] = useState<boolean>(false);

  const fetchEntities = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getEntities(minRiskFilter, statusFilter || undefined, 100);
      setEntities(data);
    } catch (err: any) {
      setError(err.message || "Failed to load tracked entities");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEntities();
  }, [statusFilter, minRiskFilter]);

  const handleInspectEntity = async (entity: Entity) => {
    setSelectedEntity(entity);
    setLoadingModal(true);
    try {
      const [bData, rData, pData, aData] = await Promise.all([
        apiService.getEntityBaselines(entity.entity_id),
        apiService.getEntityRiskHistory(entity.entity_id),
        apiService.getPeerGroupAnalysis(entity.entity_id),
        apiService.getEntityAnomalies(entity.entity_id)
      ]);
      setBaselines(bData);
      setRiskHistory(rData);
      setPeerGroup(pData);
      setAnomalies(aData);
    } catch (err: any) {
      alert(`Error loading entity details: ${err.message}`);
    } finally {
      setLoadingModal(false);
    }
  };

  const filteredEntities = entities.filter((e) => {
    if (!searchQuery) return true;
    return e.entity_id.toLowerCase().includes(searchQuery.toLowerCase());
  });

  if (loading) return <LoadingState message="Scanning Monitored Entity Catalog..." />;
  if (error) return <ErrorState message={error} onRetry={fetchEntities} />;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <span>Entity Explorer & Bounded Risk Scoring</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Bounded Entity Risk Engine (0-100), 24h Deterministic Decay & Subnet Peer-Group Analysis
          </p>
        </div>
        <button
          onClick={fetchEntities}
          className="px-3.5 py-2 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-2"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Entities</span>
        </button>
      </div>

      {/* Filters Bar */}
      <div className="glass-panel p-4 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex items-center gap-3 flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search entity IP or Hostname..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-full"
          />
        </div>

        <div className="flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Baseline Statuses</option>
            <option value="ACTIVE">ACTIVE (Baseline Ready)</option>
            <option value="INSUFFICIENT_DATA">INSUFFICIENT_DATA (&lt;20 Events)</option>
            <option value="STALE">STALE</option>
          </select>

          <select
            value={minRiskFilter ?? ''}
            onChange={(e) => setMinRiskFilter(e.target.value ? parseFloat(e.target.value) : undefined)}
            className="bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Risk Levels</option>
            <option value="70">Critical / High Risk (&gt;= 70)</option>
            <option value="40">Medium Risk (&gt;= 40)</option>
            <option value="1">Elevated Risk (&gt; 0)</option>
          </select>
        </div>
      </div>

      {/* Entities Catalog Table */}
      <div className="glass-panel p-5 space-y-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                <th className="py-2.5 px-3">Entity ID</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Baseline Status</th>
                <th className="py-2.5 px-3">Anomalies</th>
                <th className="py-2.5 px-3">Total Events</th>
                <th className="py-2.5 px-3">Last Seen</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEntities.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No matching entities found.
                  </td>
                </tr>
              ) : (
                filteredEntities.map((entity) => (
                  <tr key={entity.id} className="hover:bg-slate-900/50 transition">
                    <td className="py-3 px-3 font-bold text-cyan-400">{entity.entity_id}</td>
                    <td className="py-3 px-3 text-slate-300">{entity.entity_type}</td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold text-xs ${
                          entity.current_risk_score >= 70 ? 'text-rose-400' :
                          entity.current_risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {entity.current_risk_score.toFixed(1)} / 100
                        </span>
                        <div className="w-16 bg-slate-950 h-2 rounded overflow-hidden border border-slate-800">
                          <div
                            className={`h-full ${
                              entity.current_risk_score >= 70 ? 'bg-rose-500' :
                              entity.current_risk_score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, entity.current_risk_score)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                        entity.baseline_status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                        entity.baseline_status === 'INSUFFICIENT_DATA' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {entity.baseline_status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300 font-bold">{entity.anomaly_count}</td>
                    <td className="py-3 px-3 text-slate-400">{entity.event_count}</td>
                    <td className="py-3 px-3 text-slate-400 text-[10px]">
                      {entity.last_seen ? new Date(entity.last_seen).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => handleInspectEntity(entity)}
                        className="px-3 py-1 bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 rounded hover:bg-indigo-600/40 transition font-bold"
                      >
                        Inspect Analytics
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Entity Inspection Modal */}
      {selectedEntity && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="glass-panel border-cyan-500/40 w-full max-w-4xl max-h-[90vh] overflow-y-auto p-6 space-y-6 font-mono text-xs">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <Activity className="w-5 h-5 text-cyan-400" />
                  <span>Entity Deep Inspection: {selectedEntity.entity_id}</span>
                </h3>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Type: {selectedEntity.entity_type} | Risk Score: <span className="text-rose-400 font-bold">{selectedEntity.current_risk_score.toFixed(1)}/100</span> | Status: {selectedEntity.baseline_status}
                </p>
              </div>
              <button
                onClick={() => setSelectedEntity(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {loadingModal ? (
              <LoadingState message="Retrieving 168-hour statistical baselines & peer metrics..." />
            ) : (
              <div className="space-y-6">
                {/* 168h Statistical Baselines Grid */}
                <div className="space-y-3">
                  <h4 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-1">
                    <BarChart2 className="w-4 h-4 text-cyan-400" />
                    <span>168-Hour Statistical Baselines</span>
                  </h4>

                  {baselines.length === 0 ? (
                    <div className="p-4 rounded bg-slate-950/80 border border-slate-800 text-slate-400 text-center">
                      Status: INSUFFICIENT_DATA (Observed telemetry sample size under threshold).
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {baselines.map((b) => (
                        <div key={b.id} className="p-3 rounded bg-slate-950/90 border border-slate-800 space-y-1">
                          <div className="flex justify-between items-center border-b border-slate-800 pb-1">
                            <span className="text-cyan-400 font-bold">{b.feature_name}</span>
                            <span className="text-[10px] text-slate-500">{b.sample_count} samples</span>
                          </div>
                          <div className="grid grid-cols-3 gap-2 pt-1 text-[10px]">
                            <div><span className="text-slate-500 block">MEAN</span><span className="text-slate-200 font-bold">{b.mean_value.toFixed(2)}</span></div>
                            <div><span className="text-slate-500 block">95TH %ILE</span><span className="text-amber-400 font-bold">{b.percentile_95.toFixed(2)}</span></div>
                            <div><span className="text-slate-500 block">STD DEV</span><span className="text-slate-300">{b.standard_deviation.toFixed(2)}</span></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Peer Group Subnet Comparison */}
                {peerGroup && (
                  <div className="space-y-3">
                    <h4 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-1">
                      <Users className="w-4 h-4 text-indigo-400" />
                      <span>Peer Group Subnet Analysis ({peerGroup.peer_group_id})</span>
                    </h4>

                    <div className="p-4 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <span className="text-slate-400 text-[10px] block">PEER GROUP AVERAGE RISK</span>
                        <span className="text-indigo-300 font-bold text-base">{peerGroup.peer_group_average_risk.toFixed(1)} / 100</span>
                      </div>
                      <div>
                        <span className="text-slate-400 text-[10px] block">RISK DEVIATION FROM PEERS</span>
                        <span className={`font-bold text-base ${peerGroup.risk_deviation_from_peer >= 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {peerGroup.risk_deviation_from_peer >= 0 ? '+' : ''}{peerGroup.risk_deviation_from_peer.toFixed(1)} pts
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 text-[10px] block">PEER COHORT SIZE</span>
                        <span className="text-slate-200 font-bold text-base">{peerGroup.peer_count} Entities</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Risk History & 24h Temporal Decay Logs */}
                <div className="space-y-3">
                  <h4 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-1">
                    <TrendingUp className="w-4 h-4 text-emerald-400" />
                    <span>Risk Trajectory & 24-Hour Temporal Decay Log</span>
                  </h4>

                  {riskHistory.length === 0 ? (
                    <div className="p-3 text-slate-500 text-center">No risk modification logs recorded.</div>
                  ) : (
                    <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                      {riskHistory.map((rh) => (
                        <div key={rh.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between items-center">
                          <div>
                            <span className="text-slate-300 font-bold">{rh.contributing_factor || 'Risk Recalculation'}</span>
                            <p className="text-[10px] text-slate-500">{new Date(rh.created_at).toLocaleString()}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-slate-500">{rh.previous_score.toFixed(1)}</span>
                            <span className="text-slate-600">➔</span>
                            <span className="text-rose-400 font-bold">{rh.new_score.toFixed(1)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
