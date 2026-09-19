import React, { useState, useEffect } from 'react';
import { Search, Filter, Shield, AlertTriangle, FileText, ArrowRight, RefreshCw, CheckCircle, Database, Network, Eye } from 'lucide-react';
import { apiService } from '../services/apiService';

export const ThreatHunting: React.FC = () => {
  const [filters, setFilters] = useState({
    source_ip: '',
    destination_ip: '',
    username: '',
    hostname: '',
    event_type: '',
    severity: '',
    time_range: '24h',
    protocol: '',
    dest_port: '',
    mitre_technique: '',
    ioc_value: ''
  });

  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'workspace' | 'reports'>('workspace');
  const [huntReports, setHuntReports] = useState<any[]>([]);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [newReport, setNewReport] = useState({
    title: '',
    hypothesis: '',
    scope: '24h',
    findings: '',
    conclusion: '',
    recommended_action: ''
  });

  const handleSearch = async () => {
    setLoading(true);
    try {
      const data = await apiService.executeThreatHuntQuery(filters);
      setResults(data);
    } catch (err) {
      console.error("Threat hunt query failed", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchHuntReports = async () => {
    try {
      const reports = await apiService.getThreatHuntReports();
      setHuntReports(reports);
    } catch (err) {
      console.error("Failed to load hunt reports", err);
    }
  };

  useEffect(() => {
    handleSearch();
    fetchHuntReports();
  }, []);

  const handleSaveReport = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiService.createThreatHuntReport({
        ...newReport,
        query_params: filters
      });
      setReportModalOpen(false);
      setNewReport({ title: '', hypothesis: '', scope: '24h', findings: '', conclusion: '', recommended_action: '' });
      fetchHuntReports();
    } catch (err) {
      console.error("Failed to save hunt report", err);
    }
  };

  return (
    <div className="p-6 space-y-6 bg-[#07090e] min-h-screen text-slate-100 font-sans">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-mono font-bold text-cyan-400 flex items-center space-x-2">
            <Search className="w-5 h-5" />
            <span>Threat Hunting Workspace</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Defensive telemetry query, pivot analysis, event correlation, and hunt report documentation
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setActiveTab('workspace')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
              activeTab === 'workspace'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800'
            }`}
          >
            Hunt Query Builder
          </button>
          <button
            onClick={() => setActiveTab('reports')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
              activeTab === 'reports'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800'
            }`}
          >
            Hunt Documentation ({huntReports.length})
          </button>
        </div>
      </div>

      {activeTab === 'workspace' && (
        <div className="space-y-6">
          {/* Query Filter Builder */}
          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-5 space-y-4 shadow-lg">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center space-x-2">
                <Filter className="w-4 h-4" />
                <span>Structured Telemetry Search</span>
              </span>
              <button
                onClick={() => setFilters({
                  source_ip: '', destination_ip: '', username: '', hostname: '',
                  event_type: '', severity: '', time_range: '24h', protocol: '',
                  dest_port: '', mitre_technique: '', ioc_value: ''
                })}
                className="text-[11px] font-mono text-slate-400 hover:text-slate-200"
              >
                Reset Filters
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Source IP</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.150"
                  value={filters.source_ip}
                  onChange={(e) => setFilters({ ...filters, source_ip: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Destination IP</label>
                <input
                  type="text"
                  placeholder="e.g. 10.0.0.24"
                  value={filters.destination_ip}
                  onChange={(e) => setFilters({ ...filters, destination_ip: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Username / Entity</label>
                <input
                  type="text"
                  placeholder="e.g. admin"
                  value={filters.username}
                  onChange={(e) => setFilters({ ...filters, username: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Hostname</label>
                <input
                  type="text"
                  placeholder="e.g. srv-prod-db01"
                  value={filters.hostname}
                  onChange={(e) => setFilters({ ...filters, hostname: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Event Type</label>
                <input
                  type="text"
                  placeholder="e.g. authentication_failure"
                  value={filters.event_type}
                  onChange={(e) => setFilters({ ...filters, event_type: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">MITRE Technique</label>
                <input
                  type="text"
                  placeholder="e.g. T1110 or T1046"
                  value={filters.mitre_technique}
                  onChange={(e) => setFilters({ ...filters, mitre_technique: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">Time Scope</label>
                <select
                  value={filters.time_range}
                  onChange={(e) => setFilters({ ...filters, time_range: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs px-3 py-2 rounded-lg font-mono focus:border-cyan-500/50 outline-none"
                >
                  <option value="1h">Last 1 Hour</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                </select>
              </div>

              <div className="flex items-end space-x-2">
                <button
                  onClick={handleSearch}
                  disabled={loading}
                  className="flex-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold py-2 rounded-lg transition flex items-center justify-center space-x-2 shadow-glow-cyan"
                >
                  {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  <span>{loading ? 'Searching...' : 'Run Hunt Query'}</span>
                </button>

                <button
                  onClick={() => setReportModalOpen(true)}
                  className="bg-slate-900 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs font-mono py-2 px-3 rounded-lg transition"
                >
                  Document Hunt
                </button>
              </div>
            </div>
          </div>

          {/* Results Analytics & Pivot Metrics */}
          {results && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Matched Events</span>
                <div className="text-xl font-mono font-bold text-cyan-400 mt-1">{results.total}</div>
              </div>

              <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Unique Source IPs</span>
                <div className="text-xl font-mono font-bold text-amber-400 mt-1">{results.pivot_summary?.unique_source_ips || 0}</div>
              </div>

              <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Unique Users</span>
                <div className="text-xl font-mono font-bold text-emerald-400 mt-1">{results.pivot_summary?.unique_users || 0}</div>
              </div>

              <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Related Alerts</span>
                <div className="text-xl font-mono font-bold text-rose-400 mt-1">{results.related_alerts?.length || 0}</div>
              </div>
            </div>
          )}

          {/* Results Table */}
          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-300 uppercase">Telemetry Query Results</span>
              {results && <span className="text-xs font-mono text-slate-500">Showing {results.events?.length || 0} of {results.total} events</span>}
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3">Event Type</th>
                    <th className="px-4 py-3">Source IP</th>
                    <th className="px-4 py-3">Destination IP</th>
                    <th className="px-4 py-3">Protocol</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Details / Payload</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {results?.events?.map((ev: any) => (
                    <tr key={ev.id} className="hover:bg-slate-900/50 transition">
                      <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'N/A'}
                      </td>
                      <td className="px-4 py-3 font-semibold text-cyan-300">{ev.event_type}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setFilters({ ...filters, source_ip: ev.source_ip })}
                          className="hover:underline text-cyan-400 text-left font-mono"
                        >
                          {ev.source_ip || 'N/A'}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setFilters({ ...filters, destination_ip: ev.dest_ip })}
                          className="hover:underline text-amber-400 text-left font-mono"
                        >
                          {ev.dest_ip || 'N/A'}:{ev.dest_port || ''}
                        </button>
                      </td>
                      <td className="px-4 py-3">{ev.protocol || 'TCP'}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ev.status === 'CRITICAL' || ev.status === 'SUSPICIOUS'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        }`}>
                          {ev.status || 'NORMAL'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400 max-w-xs truncate">{ev.payload_summary || ev.details || 'N/A'}</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelectedEvent(ev)}
                          className="text-cyan-400 hover:text-cyan-300 text-xs font-mono font-semibold"
                        >
                          Pivot Details
                        </button>
                      </td>
                    </tr>
                  ))}

                  {(!results || results.events?.length === 0) && (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-slate-500 font-mono text-xs">
                        No telemetry events match the specified hunt filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Hunt Reports Tab */}
      {activeTab === 'reports' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-mono font-bold text-slate-200">Threat Hunt Reports History</h2>
            <button
              onClick={() => setReportModalOpen(true)}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold px-3 py-1.5 rounded-lg transition"
            >
              + Create Hunt Report
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {huntReports.map((report) => (
              <div key={report.id} className="bg-[#0b0f19] border border-slate-800 rounded-xl p-5 space-y-3 shadow-lg">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400">{report.hunt_id}</span>
                  <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {report.status}
                  </span>
                </div>
                <h3 className="text-sm font-mono font-bold text-slate-100">{report.title}</h3>
                <p className="text-xs font-mono text-slate-400 line-clamp-2">Hypothesis: {report.hypothesis}</p>
                <div className="text-[11px] font-mono text-slate-500 border-t border-slate-800/80 pt-2 flex items-center justify-between">
                  <span>Analyst: {report.analyst}</span>
                  <span>{new Date(report.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Create Report Modal */}
      {reportModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0b0f19] border border-cyan-500/40 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-mono font-bold text-cyan-400">Document Threat Hunt Finding</h3>
            <form onSubmit={handleSaveReport} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Hunt Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. SSH Brute Force Pattern Analysis"
                  value={newReport.title}
                  onChange={(e) => setNewReport({ ...newReport, title: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 px-3 py-2 rounded-lg outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Hypothesis</label>
                <textarea
                  rows={2}
                  placeholder="e.g. An internal host may be communicating periodically with an external destination."
                  value={newReport.hypothesis}
                  onChange={(e) => setNewReport({ ...newReport, hypothesis: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 px-3 py-2 rounded-lg outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Findings Summary</label>
                <textarea
                  rows={3}
                  placeholder="Detailed telemetry observations..."
                  value={newReport.findings}
                  onChange={(e) => setNewReport({ ...newReport, findings: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 px-3 py-2 rounded-lg outline-none"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setReportModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-2 rounded-lg shadow-glow-cyan"
                >
                  Save Hunt Report
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
