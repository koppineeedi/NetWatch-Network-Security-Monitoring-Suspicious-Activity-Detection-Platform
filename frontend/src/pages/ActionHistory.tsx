import React, { useState, useEffect } from 'react';
import {
  Shield, CheckCircle, AlertTriangle, XCircle, Clock, RefreshCw,
  RotateCcw, Lock, Play, Plus, Search, Filter
} from 'lucide-react';
import { apiService } from '../services/apiService';
import { SoarAction, SoarApproval } from '../types';

export const ActionHistory: React.FC = () => {
  const [actions, setActions] = useState<SoarAction[]>([]);
  const [approvals, setApprovals] = useState<SoarApproval[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [actionTypeFilter, setActionTypeFilter] = useState('');

  // Ad-hoc Action Request Modal
  const [isRequestOpen, setIsRequestOpen] = useState(false);
  const [actionType, setActionType] = useState('BLOCK_IP');
  const [target, setTarget] = useState('');
  const [dryRun, setDryRun] = useState(false);

  // Approval Decision Modal
  const [selectedApproval, setSelectedApproval] = useState<SoarApproval | null>(null);
  const [reason, setReason] = useState('');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [act, app] = await Promise.all([
        apiService.getSoarActions(statusFilter || undefined, actionTypeFilter || undefined),
        apiService.getSoarApprovals('PENDING')
      ]);
      setActions(act || []);
      setApprovals(app || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [statusFilter, actionTypeFilter]);

  const handleDecideApproval = async (decision: 'APPROVED' | 'DENIED') => {
    if (!selectedApproval) return;
    try {
      await apiService.decideSoarApproval(selectedApproval.approval_id, decision, reason);
      setSelectedApproval(null);
      setReason('');
      fetchData();
    } catch (e) {
      alert(String(e));
    }
  };

  const handleRollback = async (action_id: string) => {
    if (!confirm(`Are you sure you want to trigger rollback for action ${action_id}?`)) return;
    try {
      await apiService.rollbackSoarAction(action_id);
      fetchData();
    } catch (e) {
      alert(String(e));
    }
  };

  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiService.requestSoarAction({
        action_type: actionType,
        target,
        dry_run: dryRun
      });
      setIsRequestOpen(false);
      setTarget('');
      fetchData();
    } catch (e) {
      alert(String(e));
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SUCCESS':
        return <span className="px-2 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded flex items-center gap-1"><CheckCircle className="w-3 h-3" /> SUCCESS</span>;
      case 'FAILED':
        return <span className="px-2 py-0.5 text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded flex items-center gap-1"><XCircle className="w-3 h-3" /> FAILED</span>;
      case 'DRY_RUN':
        return <span className="px-2 py-0.5 text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded flex items-center gap-1"><Play className="w-3 h-3" /> DRY_RUN</span>;
      case 'PENDING_APPROVAL':
        return <span className="px-2 py-0.5 text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded flex items-center gap-1"><Clock className="w-3 h-3" /> PENDING_APPROVAL</span>;
      case 'NOT_CONFIGURED':
        return <span className="px-2 py-0.5 text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700 rounded flex items-center gap-1"><Lock className="w-3 h-3" /> NOT_CONFIGURED</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold bg-slate-800 text-slate-300 rounded">{status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-6 rounded-xl border border-slate-800 backdrop-blur-sm">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-wide">RESPONSE ACTIONS & AUTHORIZATIONS</h1>
              <p className="text-xs text-slate-400 mt-0.5">Execution Log, Pending Approvals, Real Integration Diagnostics & Rollback Control</p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setIsRequestOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs transition"
          >
            <Plus className="w-4 h-4" />
            New Action Request
          </button>
        </div>
      </div>

      {/* Pending Approvals Panel */}
      {approvals.length > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 p-5 rounded-xl space-y-3">
          <h2 className="text-sm font-bold text-amber-400 font-mono flex items-center gap-2">
            <Clock className="w-4 h-4" /> PENDING AUTHORIZATION QUEUE ({approvals.length})
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {approvals.map((app) => (
              <div key={app.approval_id} className="p-3 bg-slate-950/80 rounded border border-amber-500/40 flex items-center justify-between">
                <div>
                  <div className="text-xs font-mono font-bold text-amber-300">{app.approval_id}</div>
                  <div className="text-xs text-slate-400">Action: {app.action_id}</div>
                  <div className="text-[10px] text-amber-400 font-mono mt-1">Requires: {app.required_role}</div>
                </div>
                <button
                  onClick={() => setSelectedApproval(app)}
                  className="px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold rounded transition"
                >
                  Review
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action Table */}
      <div className="bg-slate-900/50 rounded-xl border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200 font-mono">ACTION EXECUTION LOG</h2>
          <div className="flex items-center gap-3">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded p-1.5"
            >
              <option value="">All Statuses</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILED">FAILED</option>
              <option value="DRY_RUN">DRY_RUN</option>
              <option value="PENDING_APPROVAL">PENDING_APPROVAL</option>
              <option value="NOT_CONFIGURED">NOT_CONFIGURED</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Action ID</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Requested By</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Rollback</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {actions.map((act) => (
                <tr key={act.action_id} className="hover:bg-slate-800/40">
                  <td className="py-3 px-4 text-cyan-400 font-bold">{act.action_id}</td>
                  <td className="py-3 px-4 font-bold">{act.action_type}</td>
                  <td className="py-3 px-4 text-slate-200">{act.target}</td>
                  <td className="py-3 px-4">{getStatusBadge(act.status)}</td>
                  <td className="py-3 px-4 text-slate-400">{act.requested_by}</td>
                  <td className="py-3 px-4 text-slate-500">{new Date(act.created_at).toLocaleString()}</td>
                  <td className="py-3 px-4 text-right">
                    {act.rollback_available && act.status === 'SUCCESS' && act.rollback_status === 'NONE' ? (
                      <button
                        onClick={() => handleRollback(act.action_id)}
                        className="px-2.5 py-1 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 rounded text-[10px] font-bold flex items-center gap-1 ml-auto"
                      >
                        <RotateCcw className="w-3 h-3" /> Rollback
                      </button>
                    ) : (
                      <span className="text-[10px] text-slate-600 font-mono">{act.rollback_status || 'N/A'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Decision Modal */}
      {selectedApproval && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-slate-100 font-mono">REVIEW AUTHORIZATION REQUEST</h3>
            <div className="text-xs text-slate-300 space-y-1 bg-slate-950 p-3 rounded border border-slate-800">
              <div>Approval ID: <span className="font-mono text-amber-400">{selectedApproval.approval_id}</span></div>
              <div>Action ID: <span className="font-mono text-cyan-400">{selectedApproval.action_id}</span></div>
              <div>Required Role: <span className="font-mono text-slate-200">{selectedApproval.required_role}</span></div>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Decision Reason / Justification:</label>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Enter justification for decision..."
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 h-20"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setSelectedApproval(null)} className="px-4 py-2 bg-slate-800 text-slate-300 rounded text-xs">Cancel</button>
              <button
                onClick={() => handleDecideApproval('DENIED')}
                className="px-4 py-2 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded text-xs font-bold"
              >
                Deny
              </button>
              <button
                onClick={() => handleDecideApproval('APPROVED')}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded text-xs"
              >
                Approve & Execute
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ad-hoc Request Modal */}
      {isRequestOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <form onSubmit={handleRequestSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-slate-100 font-mono">REQUEST RESPONSE ACTION</h3>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Action Type:</label>
              <select
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
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

            <div>
              <label className="text-xs text-slate-400 block mb-1">Target (IP, Host, PID, Username):</label>
              <input
                type="text"
                required
                placeholder="e.g. 192.168.1.100 or 4452 or admin_user"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="dry_run_check"
                checked={dryRun}
                onChange={(e) => setDryRun(e.target.checked)}
                className="rounded bg-slate-950 border-slate-800"
              />
              <label htmlFor="dry_run_check" className="text-xs text-slate-300 font-mono">Execute as Dry-Run Simulation</label>
            </div>

            <div className="flex justify-end gap-3 pt-2 border-t border-slate-800">
              <button type="button" onClick={() => setIsRequestOpen(false)} className="px-4 py-2 bg-slate-800 text-slate-300 rounded text-xs">Cancel</button>
              <button type="submit" className="px-4 py-2 bg-cyan-500 text-slate-950 font-bold rounded text-xs hover:bg-cyan-400">Submit Request</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
