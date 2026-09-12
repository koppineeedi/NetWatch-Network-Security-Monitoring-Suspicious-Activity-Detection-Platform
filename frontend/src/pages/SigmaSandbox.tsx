import React, { useState, useEffect } from 'react';
import {
  Play, FileCode, Clock, Shield, CheckCircle, AlertTriangle, XCircle,
  Database, Activity, ArrowRight, RefreshCw, Info
} from 'lucide-react';
import { apiService } from '../services/apiService';
import { SigmaRule, SigmaSandboxResult } from '../types';

export const SigmaSandbox: React.FC = () => {
  const urlParams = new URLSearchParams(typeof window !== 'undefined' ? window.location.search : '');
  const ruleIdParam = urlParams.get('rule_id');

  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<string>(ruleIdParam || '');
  const [useCustomYaml, setUseCustomYaml] = useState(false);
  const [customYaml, setCustomYaml] = useState('');
  const [hours, setHours] = useState(24);
  const [logSource, setLogSource] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SigmaSandboxResult | null>(null);

  useEffect(() => {
    apiService.getSigmaRules().then((data) => {
      setRules(data || []);
      if (ruleIdParam) {
        setSelectedRuleId(ruleIdParam);
      } else if (data && data.length > 0) {
        setSelectedRuleId(data[0].rule_id);
      }
    }).catch(console.error);
  }, [ruleIdParam]);

  const handleRunTest = async () => {
    setLoading(true);
    setResult(null);
    try {
      const payload: any = { hours, log_source: logSource || undefined };
      if (useCustomYaml) {
        if (!customYaml.trim()) {
          alert("Please enter YAML content for custom test.");
          setLoading(false);
          return;
        }
        payload.raw_yaml = customYaml;
      } else {
        if (!selectedRuleId) {
          alert("Please select a Sigma rule.");
          setLoading(false);
          return;
        }
        payload.rule_id = selectedRuleId;
      }

      const res = await apiService.runSigmaSandbox(payload);
      setResult(res);
    } catch (err: any) {
      alert(err.message || "Sandbox execution failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
          <Play className="w-7 h-7 text-indigo-400" />
          Detection Sandbox
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Safely test Sigma detection rules against real historical telemetry and logs without generating production alerts.
        </p>
      </div>

      {/* Test Banner Notice */}
      <div className="bg-indigo-950/40 border border-indigo-700/50 rounded-xl p-4 flex items-center gap-3">
        <Info className="w-6 h-6 text-indigo-400 flex-shrink-0" />
        <div className="text-xs text-indigo-200">
          <span className="font-semibold uppercase tracking-wider block">Sandbox Testing Policy</span>
          Evaluates rules strictly against real historical database records. Results preview detection performance and matched fields, but will <span className="underline font-semibold text-white">NEVER</span> activate rules or create live production alerts.
        </div>
      </div>

      {/* Control Panel */}
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 space-y-6">
        <div className="flex flex-wrap gap-4 border-b border-slate-700/50 pb-4">
          <button
            onClick={() => setUseCustomYaml(false)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${!useCustomYaml ? 'bg-indigo-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
          >
            Select Existing Rule
          </button>
          <button
            onClick={() => setUseCustomYaml(true)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${useCustomYaml ? 'bg-indigo-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}
          >
            Custom YAML Editor
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {!useCustomYaml ? (
            <div>
              <label className="block text-slate-300 text-xs font-semibold mb-2">Select Sigma Rule</label>
              <select
                value={selectedRuleId}
                onChange={(e) => setSelectedRuleId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-indigo-500"
              >
                {rules.map((r) => (
                  <option key={r.id} value={r.rule_id}>
                    {r.title} ({r.rule_id}) [{r.level.toUpperCase()}]
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="md:col-span-3">
              <label className="block text-slate-300 text-xs font-semibold mb-2">Custom Sigma YAML</label>
              <textarea
                rows={8}
                value={customYaml}
                onChange={(e) => setCustomYaml(e.target.value)}
                placeholder="Paste raw Sigma YAML rule content here..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
          )}

          <div>
            <label className="block text-slate-300 text-xs font-semibold mb-2">Historical Time Window</label>
            <select
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-indigo-500"
            >
              <option value={1}>Last 1 Hour</option>
              <option value={6}>Last 6 Hours</option>
              <option value={24}>Last 24 Hours (1 Day)</option>
              <option value={72}>Last 72 Hours (3 Days)</option>
              <option value={168}>Last 168 Hours (7 Days)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-300 text-xs font-semibold mb-2">Filter Data Source (Optional)</label>
            <select
              value={logSource}
              onChange={(e) => setLogSource(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-indigo-500"
            >
              <option value="">All Telemetry & Log Sources</option>
              <option value="LOCAL_NETWORK">LOCAL_NETWORK (psutil)</option>
              <option value="LOCAL_SYSTEM">LOCAL_SYSTEM</option>
              <option value="LOG_FILE">LOG_FILE</option>
              <option value="UDP_SYSLOG">UDP_SYSLOG</option>
              <option value="AWS_CLOUDTRAIL">AWS_CLOUDTRAIL</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleRunTest}
            disabled={loading}
            className="flex items-center gap-2 px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {loading ? "Executing Sandbox..." : "Run Sandbox Test"}
          </button>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Result Header Badge */}
          <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-700/50 pb-4">
              <div>
                <span className="text-xs uppercase font-bold tracking-wider text-slate-400">Sandbox Execution Report</span>
                <h2 className="text-xl font-bold text-slate-100 mt-0.5">{result.rule_title || result.rule_id}</h2>
              </div>
              <div>
                {result.status === 'SUCCESS' && (
                  <span className="px-3 py-1 bg-emerald-900/50 text-emerald-300 border border-emerald-700/50 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <CheckCircle className="w-4 h-4" /> SUCCESS
                  </span>
                )}
                {result.status === 'INSUFFICIENT_DATA' && (
                  <span className="px-3 py-1 bg-amber-900/50 text-amber-300 border border-amber-700/50 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" /> INSUFFICIENT DATA
                  </span>
                )}
                {result.status === 'ERROR' && (
                  <span className="px-3 py-1 bg-red-900/50 text-red-300 border border-red-700/50 rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <XCircle className="w-4 h-4" /> ERROR
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 text-xs block">Historical Matches</span>
                <span className="text-2xl font-bold text-indigo-400">{result.historical_matches_count}</span>
              </div>
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 text-xs block">Events Evaluated</span>
                <span className="text-2xl font-bold text-slate-200">{result.events_evaluated || 0}</span>
              </div>
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 text-xs block">Execution Duration</span>
                <span className="text-2xl font-bold text-slate-200">{result.execution_time_ms} <span className="text-xs text-slate-400 font-normal">ms</span></span>
              </div>
              <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-500 text-xs block">Mapped Fields</span>
                <span className="text-2xl font-bold text-emerald-400">{result.mapped_fields_count}</span>
              </div>
            </div>

            {result.warnings && result.warnings.length > 0 && (
              <div className="p-3 bg-amber-950/40 border border-amber-800/50 rounded-lg text-xs text-amber-300 space-y-1">
                <span className="font-semibold block">Engine Notifications:</span>
                {result.warnings.map((w, i) => (
                  <div key={i}>• {w}</div>
                ))}
              </div>
            )}
          </div>

          {/* Matched Events Table */}
          <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-700/50 font-bold text-slate-200 text-sm">
              Matched Telemetry Evidence ({result.matches.length})
            </div>
            {result.matches.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-sm">
                No matching historical events found for this rule in the specified lookback window.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-700/50 bg-slate-900/50 text-slate-400 font-semibold uppercase">
                      <th className="py-3 px-4">Event ID</th>
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4">Source IP</th>
                      <th className="py-3 px-4">Dest IP</th>
                      <th className="py-3 px-4">Explanation & Matched Fields</th>
                      <th className="py-3 px-4">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/40">
                    {result.matches.map((m, idx) => (
                      <tr key={idx} className="hover:bg-slate-700/20">
                        <td className="py-3 px-4 font-mono text-slate-300">#{m.event_id}</td>
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{m.timestamp ? new Date(m.timestamp).toLocaleString() : 'N/A'}</td>
                        <td className="py-3 px-4 font-mono text-indigo-300">{m.source_ip || 'N/A'}</td>
                        <td className="py-3 px-4 font-mono text-slate-300">{m.dest_ip ? `${m.dest_ip}:${m.dest_port || ''}` : 'N/A'}</td>
                        <td className="py-3 px-4 text-slate-200">
                          <div className="font-medium text-slate-100">{m.explanation}</div>
                          <div className="flex flex-wrap gap-1.5 mt-1">
                            {m.matched_fields.map((mf, i) => (
                              <span key={i} className="px-1.5 py-0.5 bg-slate-950 text-slate-300 rounded font-mono text-[10px] border border-slate-800">
                                {mf.sigma_field} ({mf.netwatch_field}) = "{String(mf.observed)}"
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-900/40 text-orange-400 border border-orange-700/50">
                            {m.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
