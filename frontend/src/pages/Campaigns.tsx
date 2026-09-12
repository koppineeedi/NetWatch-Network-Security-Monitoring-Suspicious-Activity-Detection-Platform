import React, { useState, useEffect } from 'react';
import { Zap, ShieldAlert, Activity, RefreshCw, Layers, Clock, AlertTriangle, ChevronRight, X, CheckCircle } from 'lucide-react';
import { Campaign, CampaignEventDetails } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { ErrorState } from '../components/ErrorState';

export const Campaigns: React.FC = () => {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [clustering, setClustering] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Campaign Detail Drawer
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [campaignEvents, setCampaignEvents] = useState<CampaignEventDetails | null>(null);
  const [loadingEvents, setLoadingEvents] = useState<boolean>(false);

  const fetchCampaigns = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getCampaigns(statusFilter || undefined, 50);
      setCampaigns(data);
    } catch (err: any) {
      setError(err.message || "Failed to load attack campaigns");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, [statusFilter]);

  const handleTriggerClustering = async () => {
    setClustering(true);
    try {
      const res = await apiService.triggerCampaignClustering();
      alert(`Campaign Clustering Completed: ${res.updated_campaigns_count} campaign(s) updated.`);
      await fetchCampaigns();
    } catch (err: any) {
      alert(`Clustering Trigger Error: ${err.message}`);
    } finally {
      setClustering(false);
    }
  };

  const handleSelectCampaign = async (campaign: Campaign) => {
    setSelectedCampaign(campaign);
    setLoadingEvents(true);
    try {
      const data = await apiService.getCampaignEvents(campaign.campaign_id);
      setCampaignEvents(data);
    } catch (err: any) {
      alert(`Error loading campaign events: ${err.message}`);
    } finally {
      setLoadingEvents(false);
    }
  };

  if (loading) return <LoadingState message="Aggregating Campaign Clusters & Threat Sequences..." />;
  if (error) return <ErrorState message={error} onRetry={fetchCampaigns} />;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Zap className="w-5 h-5 text-rose-400" />
            <span>Campaign Clustering & Correlation (CMP-2026-XXXX)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            DB-Backed Multi-Event Clustering Linking Alerts, Statistical Anomalies & MITRE Techniques
          </p>
        </div>
        <button
          onClick={handleTriggerClustering}
          disabled={clustering}
          className="px-3.5 py-2 text-xs bg-rose-500/10 text-rose-300 border border-rose-500/30 rounded-lg hover:bg-rose-500/20 transition flex items-center space-x-2 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${clustering ? 'animate-spin' : ''}`} />
          <span>{clustering ? 'Clustering Events...' : 'Trigger Cluster Engine'}</span>
        </button>
      </div>

      {/* Status Filter Tabs */}
      <div className="glass-panel p-4 flex gap-2 overflow-x-auto">
        {['', 'ACTIVE', 'MONITORING', 'RESOLVED', 'CLOSED'].map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-bold transition ${
              statusFilter === st
                ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:bg-slate-900'
            }`}
          >
            {st === '' ? 'ALL CAMPAIGNS' : st}
          </button>
        ))}
      </div>

      {/* Campaign Cards List */}
      {campaigns.length === 0 ? (
        <div className="glass-panel p-8 text-center text-slate-500 font-mono">
          No campaign clusters detected. Campaigns are generated automatically when correlated security events or anomalies occur across entities.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {campaigns.map((c) => (
            <div
              key={c.id}
              onClick={() => handleSelectCampaign(c)}
              className="glass-panel p-5 space-y-3 cursor-pointer hover:border-cyan-500/50 transition relative group"
            >
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-cyan-400 text-sm">{c.campaign_id}</span>
                  <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                    c.status === 'ACTIVE' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {c.status}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 text-[10px]">RISK</span>
                  <span className="text-rose-400 font-bold text-sm">{c.risk_score.toFixed(1)}</span>
                </div>
              </div>

              <h4 className="font-bold text-slate-200 text-xs line-clamp-1">{c.name}</h4>

              <div className="grid grid-cols-3 gap-2 py-1 text-[10px] bg-slate-950/80 p-2.5 rounded border border-slate-800">
                <div>
                  <span className="text-slate-500 block">TOTAL EVENTS</span>
                  <span className="text-slate-200 font-bold">{c.event_count}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">ENTITIES</span>
                  <span className="text-cyan-400 font-bold">{c.entity_count}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">TECHNIQUES</span>
                  <span className="text-amber-400 font-bold">{c.technique_count}</span>
                </div>
              </div>

              <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                <span>First Seen: {c.first_seen ? new Date(c.first_seen).toLocaleTimeString() : 'N/A'}</span>
                <span className="text-cyan-400 font-bold flex items-center group-hover:translate-x-1 transition-transform">
                  View Timeline <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Campaign Events Drawer / Modal */}
      {selectedCampaign && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-end p-0">
          <div className="glass-panel border-l border-cyan-500/40 w-full max-w-2xl h-full overflow-y-auto p-6 space-y-6 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-rose-400" />
                  <span>Campaign Timeline: {selectedCampaign.campaign_id}</span>
                </h3>
                <p className="text-[10px] text-slate-400 mt-0.5">{selectedCampaign.name}</p>
              </div>
              <button
                onClick={() => setSelectedCampaign(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {loadingEvents ? (
              <LoadingState message="Correlating campaign events & alerts..." />
            ) : (
              <div className="space-y-6">
                {/* Summary Metrics */}
                <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950 rounded border border-slate-800">
                  <div>
                    <span className="text-slate-500 text-[10px] block">LINKED ALERTS</span>
                    <span className="text-rose-400 font-bold text-base">{campaignEvents?.alerts_count ?? 0} Alerts</span>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] block">LINKED ANOMALIES</span>
                    <span className="text-amber-400 font-bold text-base">{campaignEvents?.anomalies_count ?? 0} Anomalies</span>
                  </div>
                </div>

                {/* Linked Alerts */}
                <div className="space-y-3">
                  <h4 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-1">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span>Correlated Security Alerts</span>
                  </h4>

                  {!campaignEvents?.alerts || campaignEvents.alerts.length === 0 ? (
                    <div className="p-3 text-slate-500">No active alerts attached.</div>
                  ) : (
                    <div className="space-y-2">
                      {campaignEvents.alerts.map((a) => (
                        <div key={a.id} className="p-3 rounded bg-slate-950/80 border border-slate-800 space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-bold text-rose-400">{a.detection_type}</span>
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300">
                              {a.severity}
                            </span>
                          </div>
                          <p className="text-slate-300 text-[11px]">{a.description}</p>
                          <span className="text-[10px] text-slate-500 block">Host: {a.source_ip || 'N/A'}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Linked Statistical Anomalies */}
                <div className="space-y-3">
                  <h4 className="font-bold text-slate-200 text-sm flex items-center gap-2 border-b border-slate-800 pb-1">
                    <Activity className="w-4 h-4 text-amber-400" />
                    <span>Correlated Statistical Anomalies</span>
                  </h4>

                  {!campaignEvents?.anomalies || campaignEvents.anomalies.length === 0 ? (
                    <div className="p-3 text-slate-500">No anomalies attached.</div>
                  ) : (
                    <div className="space-y-2">
                      {campaignEvents.anomalies.map((an) => (
                        <div key={an.id} className="p-3 rounded bg-slate-950/80 border border-slate-800 space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="font-bold text-cyan-400">{an.entity_id} - {an.feature}</span>
                            <span className="text-amber-400 font-bold">Score {an.anomaly_score.toFixed(1)}</span>
                          </div>
                          <p className="text-slate-400 text-[10px]">{an.explanation}</p>
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
