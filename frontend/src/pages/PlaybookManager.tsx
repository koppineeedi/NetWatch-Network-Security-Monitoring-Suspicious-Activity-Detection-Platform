import React, { useState, useEffect } from 'react';
import {
  Play, Plus, Search, CheckCircle, AlertTriangle, XCircle,
  Shield, ToggleLeft, ToggleRight, Eye, Trash2, RefreshCw, Layers, Zap, Clock
} from 'lucide-react';
import { apiService } from '../services/apiService';
import { SoarPlaybook, PlaybookStep } from '../types';

export const PlaybookManager: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  // Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [triggerType, setTriggerType] = useState('ALERT_CREATED');
  const [approvalPolicy, setApprovalPolicy] = useState('ANALYST_APPROVAL');
  const [steps, setSteps] = useState<PlaybookStep[]>([
    { step_id: 'step_1', action: 'BLOCK_IP', continue_on_failure: false }
  ]);

  // Dry Run Modal State
  const [selectedPlaybook, setSelectedPlaybook] = useState<SoarPlaybook | null>(null);
  const [dryRunContext, setDryRunContext] = useState('{"severity": "HIGH", "source_ip": "192.168.1.50"}');
  const [dryRunResult, setDryRunResult] = useState<any>(null);
  const [dryRunning, setDryRunning] = useState(false);

  const fetchPlaybooks = async () => {
    setLoading(true);
    try {
      const data = await apiService.getSoarPlaybooks();
      setPlaybooks(data || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlaybooks();
  }, []);

  const handleToggleEnable = async (pb: SoarPlaybook) => {
    try {
      if (pb.enabled) {
        await apiService.disableSoarPlaybook(pb.playbook_id);
      } else {
        await apiService.enableSoarPlaybook(pb.playbook_id);
      }
      fetchPlaybooks();
    } catch (e) {
      alert(String(e));
    }
  };

  const handleDelete = async (playbook_id: string) => {
    if (!confirm(`Are you sure you want to delete playbook ${playbook_id}?`)) return;
    try {
      await apiService.deleteSoarPlaybook(playbook_id);
      fetchPlaybooks();
    } catch (e) {
      alert(String(e));
    }
  };

  const handleAddStep = () => {
    setSteps([
      ...steps,
      { step_id: `step_${steps.length + 1}`, action: 'NOTIFY_ANALYST', continue_on_failure: true }
    ]);
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiService.createSoarPlaybook({
        name,
        description,
        trigger_type: triggerType,
        approval_policy: approvalPolicy,
        steps
      });
      setIsCreateOpen(false);
      setName('');
      setDescription('');
      fetchPlaybooks();
    } catch (err) {
      alert(String(err));
    }
  };

  const handleRunDryRun = async () => {
    if (!selectedPlaybook) return;
    setDryRunning(true);
    setDryRunResult(null);
    try {
      const contextObj = JSON.parse(dryRunContext);
      const res = await apiService.dryRunSoarPlaybook(selectedPlaybook.playbook_id, contextObj);
      setDryRunResult(res);
    } catch (err) {
      setDryRunResult({ status: 'ERROR', error: String(err) });
    } finally {
      setDryRunning(false);
    }
  };

  const filteredPlaybooks = playbooks.filter(p =>
    p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.playbook_id.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-6 rounded-xl border border-slate-800 backdrop-blur-sm">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
              <Zap className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-wide">PLAYBOOK BUILDER & MANAGER</h1>
              <p className="text-xs text-slate-400 mt-0.5">Define Automated Orchestration Rules, Steps, Approvals & Dry-Run Simulations</p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsCreateOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs transition"
          >
            <Plus className="w-4 h-4" />
            New Playbook
          </button>
        </div>
      </div>

      {/* Search & Filter */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search playbooks by ID or name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-900/60 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
      </div>

      {/* Playbooks List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredPlaybooks.map((pb) => (
          <div key={pb.playbook_id} className="bg-slate-900/50 p-5 rounded-xl border border-slate-800 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-bold text-cyan-400">{pb.playbook_id}</span>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 text-slate-400 rounded">v{pb.version}</span>
                  <button
                    onClick={() => handleToggleEnable(pb)}
                    className={`p-1 rounded transition ${pb.enabled ? 'text-emerald-400 hover:bg-emerald-500/10' : 'text-slate-500 hover:bg-slate-800'}`}
                    title={pb.enabled ? "Disable Playbook" : "Enable Playbook"}
                  >
                    {pb.enabled ? <ToggleRight className="w-5 h-5" /> : <ToggleLeft className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <h3 className="text-sm font-bold text-slate-100 font-mono mb-1">{pb.name}</h3>
              <p className="text-xs text-slate-400 line-clamp-2 mb-3">{pb.description}</p>

              <div className="space-y-1.5 text-xs text-slate-400 border-t border-slate-800/80 pt-3">
                <div className="flex justify-between">
                  <span>Trigger:</span>
                  <span className="font-mono text-slate-200">{pb.trigger_type}</span>
                </div>
                <div className="flex justify-between">
                  <span>Approval:</span>
                  <span className="font-mono text-amber-400">{pb.approval_policy}</span>
                </div>
                <div className="flex justify-between">
                  <span>Steps:</span>
                  <span className="font-mono text-slate-200">{pb.steps?.length || 0} Step(s)</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 border-t border-slate-800/80 pt-3">
              <button
                onClick={() => { setSelectedPlaybook(pb); setDryRunResult(null); }}
                className="flex-1 py-1.5 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition"
              >
                <Play className="w-3.5 h-3.5" />
                Dry-Run
              </button>
              <button
                onClick={() => handleDelete(pb.playbook_id)}
                className="p-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded transition"
                title="Delete Playbook"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Dry Run Modal */}
      {selectedPlaybook && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-xl w-full space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 font-mono">DRY-RUN PLAYBOOK SIMULATION</h3>
              <button onClick={() => setSelectedPlaybook(null)} className="text-slate-400 hover:text-slate-200">✕</button>
            </div>

            <div>
              <div className="text-xs font-bold text-cyan-400 font-mono mb-1">{selectedPlaybook.name} ({selectedPlaybook.playbook_id})</div>
              <label className="text-xs text-slate-400 block mb-1">Simulated Context (JSON):</label>
              <textarea
                value={dryRunContext}
                onChange={(e) => setDryRunContext(e.target.value)}
                className="w-full h-24 bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {dryRunResult && (
              <div className="p-3 bg-slate-950 rounded border border-slate-800 max-h-40 overflow-y-auto font-mono text-xs text-slate-300">
                <pre>{JSON.stringify(dryRunResult, null, 2)}</pre>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setSelectedPlaybook(null)} className="px-4 py-2 bg-slate-800 text-slate-300 rounded text-xs">Close</button>
              <button
                onClick={handleRunDryRun}
                disabled={dryRunning}
                className="px-4 py-2 bg-cyan-500 text-slate-950 font-bold rounded text-xs hover:bg-cyan-400"
              >
                {dryRunning ? 'Simulating...' : 'Execute Dry-Run'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Playbook Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <form onSubmit={handleCreateSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-2xl w-full space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 font-mono">CREATE NEW PLAYBOOK</h3>
              <button type="button" onClick={() => setIsCreateOpen(false)} className="text-slate-400 hover:text-slate-200">✕</button>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Playbook Name:</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400 block mb-1">Trigger Event:</label>
                <select
                  value={triggerType}
                  onChange={(e) => setTriggerType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                >
                  <option value="ALERT_CREATED">ALERT_CREATED</option>
                  <option value="SIGMA_MATCH">SIGMA_MATCH</option>
                  <option value="IOC_MATCH">IOC_MATCH</option>
                  <option value="UEBA_ANOMALY">UEBA_ANOMALY</option>
                  <option value="ENTITY_RISK_THRESHOLD">ENTITY_RISK_THRESHOLD</option>
                  <option value="MANUAL">MANUAL</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Approval Policy:</label>
              <select
                value={approvalPolicy}
                onChange={(e) => setApprovalPolicy(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
              >
                <option value="AUTOMATIC">AUTOMATIC (No Approval Needed)</option>
                <option value="ANALYST_APPROVAL">ANALYST_APPROVAL (Analyst or Admin)</option>
                <option value="ADMIN_APPROVAL">ADMIN_APPROVAL (Admin Required)</option>
                <option value="MANUAL_ONLY">MANUAL_ONLY (Manual Authorization)</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Description:</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 h-16"
              />
            </div>

            {/* Step List */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-mono font-bold text-cyan-400">PLAYBOOK STEPS</label>
                <button type="button" onClick={handleAddStep} className="text-xs text-cyan-400 hover:underline">+ Add Step</button>
              </div>

              {steps.map((st, idx) => (
                <div key={idx} className="p-3 bg-slate-950 rounded border border-slate-800 flex items-center justify-between gap-3">
                  <span className="text-xs font-mono text-slate-400">Step {idx + 1}:</span>
                  <select
                    value={st.action}
                    onChange={(e) => {
                      const copy = [...steps];
                      copy[idx].action = e.target.value;
                      setSteps(copy);
                    }}
                    className="bg-slate-900 border border-slate-800 text-xs text-slate-200 p-1.5 rounded flex-1"
                  >
                    <option value="BLOCK_IP">BLOCK_IP</option>
                    <option value="UNBLOCK_IP">UNBLOCK_IP</option>
                    <option value="ISOLATE_HOST">ISOLATE_HOST</option>
                    <option value="RESTORE_HOST">RESTORE_HOST</option>
                    <option value="KILL_PROCESS">KILL_PROCESS</option>
                    <option value="DISABLE_ACCOUNT">DISABLE_ACCOUNT</option>
                    <option value="ENABLE_ACCOUNT">ENABLE_ACCOUNT</option>
                    <option value="NOTIFY_ANALYST">NOTIFY_ANALYST</option>
                  </select>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
              <button type="button" onClick={() => setIsCreateOpen(false)} className="px-4 py-2 bg-slate-800 text-slate-300 rounded text-xs">Cancel</button>
              <button type="submit" className="px-4 py-2 bg-cyan-500 text-slate-950 font-bold rounded text-xs hover:bg-cyan-400">Save Playbook</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
