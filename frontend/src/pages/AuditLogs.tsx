import React, { useState, useEffect } from 'react';
import { Shield, FileText, Search, RefreshCw, Filter, CheckCircle, Clock, User as UserIcon } from 'lucide-react';
import { apiService } from '../services/apiService';

export const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [filters, setFilters] = useState({
    user: '',
    action: '',
    resource_type: '',
    search: ''
  });

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await apiService.getAuditLogs(filters);
      setLogs(data.logs || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error("Failed to load audit logs", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="p-6 space-y-6 bg-[#07090e] min-h-screen text-slate-100 font-sans">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-mono font-bold text-cyan-400 flex items-center space-x-2">
            <FileText className="w-5 h-5" />
            <span>SOC Audit Log Trail</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Tamper-evident security audit trail of analyst state transitions, triage actions, rule edits, SOAR approvals, and threat hunt executions
          </p>
        </div>

        <button
          onClick={fetchLogs}
          disabled={loading}
          className="bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs font-mono px-3 py-1.5 rounded-lg transition flex items-center space-x-2"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Audit Trail</span>
        </button>
      </div>

      {/* Filter Builder */}
      <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-4 space-y-3 shadow-lg">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Search Keywords</label>
            <input
              type="text"
              placeholder="Search user, action, details..."
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono outline-none"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Analyst User</label>
            <input
              type="text"
              placeholder="e.g. admin"
              value={filters.user}
              onChange={(e) => setFilters({ ...filters, user: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono outline-none"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Action Type</label>
            <input
              type="text"
              placeholder="e.g. ALERT_ASSIGN, HUNT_EXECUTE"
              value={filters.action}
              onChange={(e) => setFilters({ ...filters, action: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono outline-none"
            />
          </div>

          <div className="flex items-end space-x-2">
            <button
              onClick={fetchLogs}
              className="flex-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold py-2 rounded-lg transition"
            >
              Filter Audit Logs
            </button>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-mono font-bold text-slate-300 uppercase">Audit History ({total} records)</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">User / Actor</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Resource Type</th>
                <th className="px-4 py-3">Resource ID</th>
                <th className="px-4 py-3">Result</th>
                <th className="px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/50 transition">
                  <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                    {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}
                  </td>
                  <td className="px-4 py-3 font-semibold text-cyan-300 flex items-center space-x-2">
                    <UserIcon className="w-3.5 h-3.5 text-slate-500" />
                    <span>{log.user}</span>
                  </td>
                  <td className="px-4 py-3 font-bold text-slate-200">{log.action}</td>
                  <td className="px-4 py-3 text-slate-400">{log.resource_type}</td>
                  <td className="px-4 py-3 text-amber-400 font-mono">{log.resource_id}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      {log.result}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-400 max-w-sm truncate">{log.details || 'N/A'}</td>
                </tr>
              ))}

              {logs.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500 font-mono text-xs">
                    No audit log records found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
