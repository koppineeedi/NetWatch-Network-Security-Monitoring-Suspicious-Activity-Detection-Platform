import React, { useState, useEffect } from 'react';
import {
  Zap, Shield, Play, CheckCircle, AlertTriangle, XCircle, Clock,
  RefreshCw, Cpu, Check, ArrowRight, Activity, Server, Lock
} from 'lucide-react';
import { apiService } from '../services/apiService';
import { SoarStatistics, SoarAction, SoarApproval, SoarPlaybook } from '../types';

interface SOARDashboardProps {
  onNavigate?: (path: string) => void;
}

export const SOARDashboard: React.FC<SOARDashboardProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<SoarStatistics | null>(null);
  const [recentActions, setRecentActions] = useState<SoarAction[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<SoarApproval[]>([]);
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [s, a, p, pb] = await Promise.all([
        apiService.getSoarStatistics(),
        apiService.getSoarActions(),
        apiService.getSoarApprovals('PENDING'),
        apiService.getSoarPlaybooks()
      ]);
      setStats(s);
      setRecentActions(a || []);
      setPendingApprovals(p || []);
      setPlaybooks(pb || []);
    } catch (e) {
      console.error('Failed to load SOAR dashboard data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleNavigate = (path: string) => {
    if (onNavigate) {
      onNavigate(path);
    } else {
      window.location.href = path;
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
        return <span className="px-2 py-0.5 text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded">{status}</span>;
    }
  };

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
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-wide">
                SECURITY ORCHESTRATION, AUTOMATION & RESPONSE (SOAR)
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Automated Playbooks, Real OS Integrations, Approval Workflows, and Dry-Run Incident Response
              </p>
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
            onClick={() => handleNavigate('/soar/playbooks')}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs transition"
          >
            <Play className="w-4 h-4" />
            Playbook Builder
          </button>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>ACTIVE PLAYBOOKS</span>
            <Zap className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {stats?.enabled_playbooks || 0} <span className="text-xs font-normal text-slate-500">/ {stats?.total_playbooks || 0}</span>
          </div>
        </div>

        <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>PENDING APPROVALS</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono">
            {stats?.pending_approvals || 0}
          </div>
        </div>

        <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>SUCCESSFUL ACTIONS</span>
            <CheckCircle className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">
            {stats?.successful_actions || 0}
          </div>
        </div>

        <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>DRY-RUN SIMULATIONS</span>
            <Play className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 font-mono">
            {stats?.dry_run_actions || 0}
          </div>
        </div>
      </div>

      {/* Integration Status Section */}
      <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800">
        <h2 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider mb-4 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          REAL OS & SYSTEM INTEGRATION STATUS
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
          {stats?.integrations_status && Object.entries(stats.integrations_status).map(([name, status]) => (
            <div key={name} className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 flex flex-col justify-between">
              <div className="text-xs font-mono text-slate-400 truncate mb-2">{name}</div>
              <div>{getStatusBadge(status)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Playbooks & Pending Approvals Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Playbooks List */}
        <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center gap-2">
              <Play className="w-4 h-4 text-cyan-400" />
              Automated Playbooks
            </h2>
            <button
              onClick={() => handleNavigate('/soar/playbooks')}
              className="text-xs text-cyan-400 hover:underline flex items-center gap-1 font-mono"
            >
              View All <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3 flex-1">
            {playbooks.slice(0, 4).map((pb) => (
              <div key={pb.playbook_id} className="p-3.5 bg-slate-950/40 rounded-lg border border-slate-800/80 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-200">{pb.name}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 text-slate-400 rounded">v{pb.version}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 line-clamp-1">{pb.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${pb.enabled ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-500'}`}>
                    {pb.enabled ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Pending Approvals */}
        <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200 font-mono uppercase tracking-wider flex items-center gap-2">
              <Clock className="w-4 h-4 text-amber-400" />
              Pending Authorization Queue
            </h2>
            <button
              onClick={() => handleNavigate('/soar/actions')}
              className="text-xs text-amber-400 hover:underline flex items-center gap-1 font-mono"
            >
              Manage Actions <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3 flex-1">
            {pendingApprovals.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono border border-dashed border-slate-800 rounded-lg">
                No pending authorization requests.
              </div>
            ) : (
              pendingApprovals.map((app) => (
                <div key={app.approval_id} className="p-3.5 bg-slate-950/40 rounded-lg border border-amber-500/30 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-amber-300">{app.approval_id}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded">{app.required_role} REQUIRED</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">Action: <span className="font-mono text-slate-200">{app.action_id}</span></div>
                  </div>
                  <button
                    onClick={() => handleNavigate('/soar/actions')}
                    className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-semibold rounded border border-amber-500/40 transition"
                  >
                    Review
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
