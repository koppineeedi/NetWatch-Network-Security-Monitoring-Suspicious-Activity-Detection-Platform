import React, { useState, useEffect } from 'react';
import { Shield, Layers, AlertCircle, CheckCircle, RefreshCw, BarChart2 } from 'lucide-react';
import { apiService } from '../services/apiService';

export const MitreCoverage: React.FC = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedTactic, setSelectedTactic] = useState<any>(null);

  const fetchCoverage = async () => {
    setLoading(true);
    try {
      const res = await apiService.getMitreCoverage();
      setData(res);
      if (res.tactics && res.tactics.length > 0) {
        setSelectedTactic(res.tactics[0]);
      }
    } catch (err) {
      console.error("Failed to load MITRE ATT&CK coverage", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCoverage();
  }, []);

  if (loading) {
    return (
      <div className="p-8 text-cyan-400 font-mono text-xs flex items-center justify-center min-h-screen">
        <RefreshCw className="w-5 h-5 animate-spin mr-2" />
        <span>Calculating Real MITRE ATT&CK Matrix Coverage...</span>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 bg-[#07090e] min-h-screen text-slate-100 font-sans">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-mono font-bold text-cyan-400 flex items-center space-x-2">
            <Shield className="w-5 h-5" />
            <span>MITRE ATT&CK Coverage Matrix</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Calculated exclusively from active backend detection rules & live firing security alerts across 12 Enterprise Tactics
          </p>
        </div>

        <button
          onClick={fetchCoverage}
          className="bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs font-mono px-3 py-1.5 rounded-lg transition flex items-center space-x-2"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Coverage</span>
        </button>
      </div>

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono">
        <div className="bg-[#0b0f19] border border-cyan-500/30 rounded-xl p-5 shadow-lg">
          <span className="text-xs text-slate-400 uppercase">Overall Matrix Coverage</span>
          <div className="text-3xl font-bold text-cyan-400 mt-2">{data?.overall_coverage_percentage}%</div>
          <p className="text-[11px] text-slate-500 mt-1">{data?.covered_tactics_count} of {data?.total_tactics_count} Tactics Covered</p>
        </div>

        <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-5 shadow-lg">
          <span className="text-xs text-slate-400 uppercase">Active Rules Analyzed</span>
          <div className="text-3xl font-bold text-emerald-400 mt-2">{data?.active_rules_analyzed}</div>
          <p className="text-[11px] text-slate-500 mt-1">Detection & Sigma Rules</p>
        </div>

        <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-5 shadow-lg">
          <span className="text-xs text-slate-400 uppercase">Firing Alerts Mapped</span>
          <div className="text-3xl font-bold text-amber-400 mt-2">{data?.total_alerts_analyzed}</div>
          <p className="text-[11px] text-slate-500 mt-1">Correlated Security Alerts</p>
        </div>

        <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-5 shadow-lg">
          <span className="text-xs text-slate-400 uppercase">Tactics Status</span>
          <div className="text-3xl font-bold text-purple-400 mt-2">{data?.covered_tactics_count} Active</div>
          <p className="text-[11px] text-slate-500 mt-1">Mapped in SOC Engine</p>
        </div>
      </div>

      {/* Tactics Grid Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
        {data?.tactics?.map((tactic: any) => (
          <button
            key={tactic.id}
            onClick={() => setSelectedTactic(tactic)}
            className={`p-3 rounded-xl border text-left transition space-y-2 font-mono ${
              selectedTactic?.id === tactic.id
                ? 'bg-cyan-500/10 border-cyan-500/60 text-cyan-300 shadow-glow-cyan'
                : tactic.covered
                ? 'bg-[#0b0f19] border-emerald-500/40 hover:border-emerald-500/70 text-slate-200'
                : 'bg-[#0b0f19] border-slate-800 hover:border-slate-700 text-slate-400'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-500">{tactic.id}</span>
              {tactic.covered ? (
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <AlertCircle className="w-3.5 h-3.5 text-slate-600" />
              )}
            </div>
            <div className="text-xs font-bold truncate">{tactic.name}</div>
            <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-slate-800/60">
              <span>{tactic.rules_count} Rules</span>
              <span className="text-amber-400">{tactic.alerts_count} Alerts</span>
            </div>
          </button>
        ))}
      </div>

      {/* Selected Tactic Details */}
      {selectedTactic && (
        <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span className="text-xs font-mono text-slate-400">{selectedTactic.id}</span>
              <h2 className="text-base font-mono font-bold text-cyan-400">{selectedTactic.name} Tactic Details</h2>
            </div>
            <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
              selectedTactic.covered
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                : 'bg-slate-800 text-slate-400'
            }`}>
              {selectedTactic.covered ? 'COVERED IN SOC' : 'NO ACTIVE RULES'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {selectedTactic.techniques?.map((tech: any) => (
              <div key={tech.id} className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-400">{tech.id}</span>
                  <span className="text-[11px] text-amber-400 font-semibold">{tech.firing_alerts_count} Alerts</span>
                </div>
                <div className="text-xs font-semibold text-slate-200">{tech.name}</div>
                
                <div className="text-[11px] text-slate-400 space-y-1 border-t border-slate-800/60 pt-2">
                  <span className="text-slate-500">Mapped Rules ({tech.mapped_rules_count}):</span>
                  {tech.mapped_rules?.length > 0 ? (
                    <ul className="list-disc list-inside text-slate-300">
                      {tech.mapped_rules.map((rName: string, idx: number) => (
                        <li key={idx} className="truncate">{rName}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-slate-600 italic">No detection rule directly mapped</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
