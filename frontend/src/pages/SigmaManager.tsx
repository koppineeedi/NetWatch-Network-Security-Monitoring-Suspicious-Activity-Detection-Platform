import React, { useState, useEffect } from 'react';
import {
  FileCode, Play, Plus, Search, CheckCircle, AlertTriangle, XCircle,
  Shield, ToggleLeft, ToggleRight, Eye, Trash2, RefreshCw, Layers
} from 'lucide-react';
import { apiService } from '../services/apiService';
import { SigmaRule, SigmaStatistics, SigmaValidationResult } from '../types';

interface SigmaManagerProps {
  onNavigate?: (path: string) => void;
}

export const SigmaManager: React.FC<SigmaManagerProps> = ({ onNavigate }) => {
  const handleNavigate = (path: string) => {
    if (onNavigate) {
      onNavigate(path);
    } else {
      window.location.href = path;
    }
  };
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [stats, setStats] = useState<SigmaStatistics | null>(null);
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);

  // Import Modal State
  const [isImportOpen, setIsImportOpen] = useState(false);
  const [yamlContent, setYamlContent] = useState('');
  const [validationResult, setValidationResult] = useState<SigmaValidationResult | null>(null);
  const [importing, setImporting] = useState(false);

  // Detail Modal State
  const [selectedRule, setSelectedRule] = useState<SigmaRule | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [rulesData, statsData] = await Promise.all([
        apiService.getSigmaRules(search, statusFilter, levelFilter),
        apiService.getSigmaStatistics()
      ]);
      setRules(rulesData || []);
      setStats(statsData || null);
    } catch (err) {
      console.error("Failed to load Sigma data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search, levelFilter, statusFilter]);

  const handleValidate = async () => {
    if (!yamlContent.trim()) return;
    try {
      const res = await apiService.validateSigmaYaml(yamlContent);
      setValidationResult(res);
    } catch (err) {
      console.error(err);
    }
  };

  const handleImport = async () => {
    if (!yamlContent.trim()) return;
    setImporting(true);
    try {
      await apiService.importSigmaRules(yamlContent);
      setIsImportOpen(false);
      setYamlContent('');
      setValidationResult(null);
      loadData();
    } catch (err: any) {
      alert(err.message || "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleToggle = async (rule: SigmaRule) => {
    try {
      if (rule.enabled) {
        await apiService.disableSigmaRule(rule.rule_id);
      } else {
        await apiService.enableSigmaRule(rule.rule_id);
      }
      loadData();
    } catch (err: any) {
      alert(err.message || "Failed to toggle rule state");
    }
  };

  const handleDelete = async (ruleId: string) => {
    if (!confirm(`Are you sure you want to delete Sigma rule '${ruleId}'?`)) return;
    try {
      await apiService.deleteSigmaRule(ruleId);
      loadData();
    } catch (err: any) {
      alert(err.message || "Failed to delete rule");
    }
  };

  const getLevelBadge = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-900/40 text-red-400 border border-red-700/50">CRITICAL</span>;
      case 'high':
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-orange-900/40 text-orange-400 border border-orange-700/50">HIGH</span>;
      case 'medium':
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-900/40 text-yellow-400 border border-yellow-700/50">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-900/40 text-blue-400 border border-blue-700/50">LOW</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'VALID':
      case 'ENABLED':
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-900/40 text-emerald-400 border border-emerald-700/50">VALID</span>;
      case 'UNSUPPORTED':
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-amber-900/40 text-amber-400 border border-amber-700/50">UNSUPPORTED</span>;
      case 'INVALID':
      case 'ERROR':
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-900/40 text-red-400 border border-red-700/50">INVALID</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">{status}</span>;
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <FileCode className="w-7 h-7 text-indigo-400" />
            Sigma Detection Rule Engine
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Production-grade Sigma YAML rule catalog, version control, and real-data evaluator.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => handleNavigate('/sigma/sandbox')}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium text-sm transition-colors"
          >
            <Play className="w-4 h-4" />
            Detection Sandbox
          </button>
          <button
            onClick={() => setIsImportOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium text-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            Import Sigma Rule
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider">Total Rules</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">{stats.total_rules}</div>
          </div>
          <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider">Enabled Rules</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{stats.enabled_rules}</div>
          </div>
          <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider">Total Matches</div>
            <div className="text-2xl font-bold text-indigo-400 mt-1">{stats.total_matches}</div>
          </div>
          <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider">Avg Exec Speed</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">{stats.average_execution_ms} <span className="text-xs text-slate-400 font-normal">ms</span></div>
          </div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4 flex flex-col md:flex-row gap-4 justify-between items-center">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Search by title, ID, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>
        <div className="flex items-center gap-3 w-full md:w-auto">
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All Statuses</option>
            <option value="VALID">Valid</option>
            <option value="UNSUPPORTED">Unsupported</option>
            <option value="INVALID">Invalid</option>
          </select>
          <button
            onClick={loadData}
            className="p-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg transition-colors"
            title="Refresh Catalog"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading Sigma Rules...</div>
        ) : rules.length === 0 ? (
          <div className="p-12 text-center">
            <FileCode className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <div className="text-slate-300 font-medium">No Sigma Rules Found</div>
            <p className="text-slate-500 text-sm mt-1">Import a Sigma YAML rule file to begin production detection evaluation.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-700/50 bg-slate-900/50 text-slate-400 text-xs font-semibold uppercase tracking-wider">
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4">Rule Title & ID</th>
                  <th className="py-3.5 px-4">Level</th>
                  <th className="py-3.5 px-4">Version</th>
                  <th className="py-3.5 px-4">MITRE ATT&CK</th>
                  <th className="py-3.5 px-4">Enabled</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/40 text-sm">
                {rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-slate-700/20 transition-colors">
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getStatusBadge(rule.status)}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-100">{rule.title}</div>
                      <div className="text-xs text-slate-400 font-mono mt-0.5">{rule.rule_id}</div>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getLevelBadge(rule.level)}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-mono text-xs">
                      v{rule.version}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {rule.tags && rule.tags.filter(t => t.toLowerCase().startsWith('attack.t')).length > 0 ? (
                          rule.tags.filter(t => t.toLowerCase().startsWith('attack.t')).map((t, idx) => (
                            <span key={idx} className="px-1.5 py-0.5 bg-slate-900 text-indigo-300 text-xs rounded border border-indigo-500/30 font-mono">
                              {t.replace('attack.', '').toUpperCase()}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 text-xs">None</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggle(rule)}
                        className="focus:outline-none"
                        title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                      >
                        {rule.enabled ? (
                          <ToggleRight className="w-7 h-7 text-emerald-400" />
                        ) : (
                          <ToggleLeft className="w-7 h-7 text-slate-600" />
                        )}
                      </button>
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap space-x-2">
                      <button
                        onClick={() => setSelectedRule(rule)}
                        className="p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded transition-colors"
                        title="View Details & YAML"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleNavigate(`/sigma/sandbox?rule_id=${rule.rule_id}`)}
                        className="p-1.5 bg-indigo-900/60 hover:bg-indigo-800 text-indigo-300 border border-indigo-700/50 rounded transition-colors"
                        title="Test in Sandbox"
                      >
                        <Play className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(rule.rule_id)}
                        className="p-1.5 bg-red-900/40 hover:bg-red-800 text-red-400 border border-red-700/50 rounded transition-colors"
                        title="Delete Rule"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Import Modal */}
      {isImportOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <FileCode className="w-5 h-5 text-indigo-400" />
                Import Sigma YAML Rule
              </h3>
              <button
                onClick={() => setIsImportOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>
            <div className="p-4 space-y-4 overflow-y-auto flex-1">
              <div>
                <label className="block text-slate-300 text-xs font-semibold mb-1">Sigma Rule YAML Content</label>
                <textarea
                  rows={10}
                  value={yamlContent}
                  onChange={(e) => setYamlContent(e.target.value)}
                  placeholder={`title: Suspicious Outbound Connection\nid: 12345678-1234-1234-1234-123456789abc\nstatus: experimental\ndescription: Detects unusual outbound network activity\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    dst_port: 4444\n  condition: selection\nlevel: high`}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
                />
              </div>

              {validationResult && (
                <div className={`p-3 rounded-lg border text-xs space-y-1 ${validationResult.valid ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-300' : 'bg-red-950/40 border-red-800/50 text-red-300'}`}>
                  <div className="font-semibold flex items-center gap-1.5">
                    {validationResult.valid ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                    Validation Status: {validationResult.status}
                  </div>
                  {validationResult.errors.map((err, i) => (
                    <div key={i}>• {err}</div>
                  ))}
                  {validationResult.unsupported_features.map((un, i) => (
                    <div key={i} className="text-amber-400">• {un}</div>
                  ))}
                </div>
              )}
            </div>
            <div className="p-4 border-t border-slate-800 flex justify-end gap-3 bg-slate-950/50">
              <button
                onClick={handleValidate}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm font-medium transition-colors"
              >
                Validate YAML
              </button>
              <button
                onClick={handleImport}
                disabled={importing}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              >
                {importing ? "Importing..." : "Save & Import"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rule Details Modal */}
      {selectedRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <div>
                <h3 className="text-lg font-bold text-slate-100">{selectedRule.title}</h3>
                <div className="text-xs text-slate-400 font-mono mt-0.5">{selectedRule.rule_id}</div>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>
            <div className="p-4 space-y-4 overflow-y-auto flex-1 text-xs">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-500 block">Level</span>
                  <span className="font-semibold text-slate-200">{selectedRule.level.toUpperCase()}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Status</span>
                  <span className="font-semibold text-slate-200">{selectedRule.status}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Version</span>
                  <span className="font-semibold text-slate-200">v{selectedRule.version}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Author</span>
                  <span className="font-semibold text-slate-200">{selectedRule.author || 'System'}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Raw Sigma YAML</span>
                <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-slate-300 overflow-x-auto">
                  {selectedRule.raw_yaml}
                </pre>
              </div>
            </div>
            <div className="p-4 border-t border-slate-800 flex justify-end gap-3 bg-slate-950/50">
              <button
                onClick={() => {
                  const rid = selectedRule.rule_id;
                  setSelectedRule(null);
                  handleNavigate(`/sigma/sandbox?rule_id=${rid}`);
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                Test in Detection Sandbox
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
