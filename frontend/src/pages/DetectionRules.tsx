import React, { useState, useEffect } from 'react';
import { Sliders, Plus, CheckCircle, ShieldAlert, Lock, ToggleLeft, ToggleRight, RefreshCw } from 'lucide-react';
import { DetectionRule, UserRole } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

interface DetectionRulesProps {
  rules?: DetectionRule[];
  onToggleRule?: (id: number, enabled: boolean) => void;
  onCreateRule?: (rule: Partial<DetectionRule>) => void;
  userRole?: UserRole;
}

export const DetectionRules: React.FC<DetectionRulesProps> = ({
  userRole = 'SOC_ANALYST'
}) => {
  const [ruleList, setRuleList] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isCreateOpen, setIsCreateOpen] = useState(false);

  const [newRuleCode, setNewRuleCode] = useState('');
  const [newRuleName, setNewRuleName] = useState('');
  const [newCategory, setNewCategory] = useState('ANOMALY');
  const [newDesc, setNewDesc] = useState('');

  const canModify = true; // SOC Analyst/Manager can toggle rule status

  const fetchRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getRules();
      setRuleList(data);
    } catch (err: any) {
      setError(err.message || "Failed to load detection rules");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (id: number, currentEnabled: boolean) => {
    try {
      await apiService.toggleRule(id, !currentEnabled);
      await fetchRules();
    } catch (err: any) {
      alert(`Failed to update rule: ${err.message}`);
    }
  };

  const handleSubmitNewRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleCode || !newRuleName) return;

    try {
      await apiService.createRule({
        rule_code: newRuleCode,
        name: newRuleName,
        category: newCategory,
        condition_desc: newDesc,
        severity: 'HIGH',
        threshold: 10,
        time_window: 60,
        enabled: true
      });
      setIsCreateOpen(false);
      setNewRuleCode('');
      setNewRuleName('');
      setNewDesc('');
      await fetchRules();
    } catch (err: any) {
      alert(`Failed to create rule: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <span>Detection Rule Management & Heuristic Tuning</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative Backend Behavioral Rules & Configuration State
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchRules}
            title="Refresh Rules"
            className="p-2 rounded bg-slate-900 text-slate-300 hover:text-cyan-400 border border-slate-800 transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-4 py-2 text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition flex items-center space-x-1.5 shadow-glow-cyan"
          >
            <Plus className="w-4 h-4" />
            <span>Create Custom Rule</span>
          </button>
        </div>
      </div>

      {/* Rules Content */}
      {loading ? (
        <LoadingState message="Loading detection rules from database..." />
      ) : error ? (
        <ErrorState message={error} onRetry={fetchRules} />
      ) : ruleList.length === 0 ? (
        <EmptyState title="No Detection Rules Configured" message="No rules found in database." />
      ) : (
        <div className="glass-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase">
                  <th className="py-3 px-4">Rule Code</th>
                  <th className="py-3 px-4">Rule Name</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Condition Logic</th>
                  <th className="py-3 px-4">Threshold / Window</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4 text-right">Status / Toggle</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {ruleList.map((rule) => (
                  <tr key={rule.id} className="hover:bg-slate-900/60 transition">
                    <td className="py-3 px-4 text-cyan-400 font-bold">{rule.rule_code}</td>
                    <td className="py-3 px-4 font-semibold text-slate-100">{rule.name}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 text-[10px] bg-slate-800 text-slate-300 rounded border border-slate-700">
                        {rule.category}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] max-w-xs">{rule.condition_desc}</td>
                    <td className="py-3 px-4 text-[11px] text-slate-300">
                      &gt;{rule.threshold} in {rule.time_window}s
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                        rule.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                        rule.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                        'bg-slate-700 text-slate-300'
                      }`}>
                        {rule.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleToggle(rule.id, rule.enabled)}
                        className={`px-3 py-1 text-xs rounded transition flex items-center space-x-1.5 ml-auto ${
                          rule.enabled
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
                            : 'bg-slate-800 text-slate-500 border border-slate-700 hover:bg-slate-750'
                        }`}
                      >
                        {rule.enabled ? <ToggleRight className="w-4 h-4 text-emerald-400" /> : <ToggleLeft className="w-4 h-4 text-slate-500" />}
                        <span>{rule.enabled ? 'ACTIVE' : 'DISABLED'}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Rule Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm font-mono text-xs">
          <div className="glass-panel w-full max-w-md p-6 space-y-4 border-cyan-500/30">
            <h3 className="text-sm font-bold text-slate-100">Create Custom Detection Rule</h3>
            <form onSubmit={handleSubmitNewRule} className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Rule Code (e.g. R-CUST-01)</label>
                <input
                  type="text"
                  required
                  placeholder="R-CUST-01"
                  value={newRuleCode}
                  onChange={(e) => setNewRuleCode(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  placeholder="Unusual High Frequency Connections"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Category</label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                >
                  <option value="RECONNAISSANCE">RECONNAISSANCE</option>
                  <option value="CREDENTIAL_ACCESS">CREDENTIAL_ACCESS</option>
                  <option value="EXFILTRATION">EXFILTRATION</option>
                  <option value="COMMAND_AND_CONTROL">COMMAND_AND_CONTROL</option>
                  <option value="ANOMALY">ANOMALY</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Condition Description</label>
                <textarea
                  rows={3}
                  placeholder="Triggers when host sends >50 connection attempts in 60s"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded hover:bg-cyan-500/30"
                >
                  Deploy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
