import React, { useState, useEffect } from 'react';
import { ShieldAlert, Filter, Eye, RefreshCw, AlertTriangle, ExternalLink, Play, Radio } from 'lucide-react';
import { SecurityAlert, NetworkEvent } from '../types';
import { apiService } from '../services/apiService';
import { websocketService } from '../services/websocketService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { Modal } from '../components/Modal';

export const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [evidenceEvents, setEvidenceEvents] = useState<NetworkEvent[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState<boolean>(false);
  const [creatingInv, setCreatingInv] = useState<boolean>(false);

  const fetchAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getAlerts(statusFilter, severityFilter);
      setAlerts(data);
    } catch (err: any) {
      setError(err.message || "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [statusFilter, severityFilter]);

  // Real-time WebSocket subscription for live alerts stream
  useEffect(() => {
    const unsubscribe = websocketService.subscribe('alert', (liveAlert: any) => {
      if (!liveAlert || !liveAlert.id) return;
      setAlerts((prevAlerts) => {
        if (prevAlerts.some((a) => a.id === liveAlert.id)) return prevAlerts;
        return [liveAlert as SecurityAlert, ...prevAlerts].slice(0, 100);
      });
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const handleOpenDetail = async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setLoadingEvidence(true);
    try {
      const evts = await apiService.getAlertEvidenceEvents(alert.id);
      setEvidenceEvents(evts);
    } catch {
      setEvidenceEvents([]);
    } finally {
      setLoadingEvidence(false);
    }
  };

  const handleStartInvestigation = async () => {
    if (!selectedAlert) return;
    setCreatingInv(true);
    try {
      const inv = await apiService.createInvestigationFromAlert(selectedAlert.id);
      alert(`Investigation Case Created: ${inv.case_number}`);
      setSelectedAlert(null);
      await fetchAlerts();
    } catch (err: any) {
      alert(`Failed to start investigation: ${err.message}`);
    } finally {
      setCreatingInv(false);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            <span>SOC Security Alerts Triage Queue</span>
            <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1">
              <Radio className="w-3 h-3 animate-pulse" />
              LIVE TRIAGE ACTIVE
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative Evidence-Backed Detections & Analyst Triage Pipeline
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          className="px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Alerts</span>
        </button>
      </div>

      {/* Filter Controls Bar */}
      <div className="glass-panel p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-2 text-slate-400">
          <Filter className="w-4 h-4 text-cyan-400" />
          <span>Filter Queue:</span>
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="TRUE_POSITIVE">True Positive</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="RESOLVED">Resolved</option>
            <option value="CLOSED">Closed</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Main Content */}
      {loading ? (
        <LoadingState message="Loading security alerts queue..." />
      ) : error ? (
        <ErrorState message={error} onRetry={fetchAlerts} />
      ) : alerts.length === 0 ? (
        <EmptyState title="No active alerts." message="No security alerts generated from backend detection engine." />
      ) : (
        <div className="glass-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase">
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Alert Title / Rule</th>
                  <th className="py-3 px-4">Source & Target IP</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {alerts.map((alt) => (
                  <tr key={alt.id} className="hover:bg-slate-900/60 transition">
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(alt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-100">
                      <div>{alt.detection_type}</div>
                      <div className="text-[10px] text-slate-500 font-mono">Rule: {alt.rule_id || 'BEHAVIORAL'}</div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-cyan-400 font-bold">{alt.source_ip || 'N/A'}</div>
                      <div className="text-[10px] text-slate-500">&rarr; {alt.dest_ip || 'N/A'}</div>
                    </td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={alt.severity} />
                    </td>
                    <td className="py-3 px-4 text-emerald-400 font-bold">
                      {alt.risk_score ? alt.risk_score.toFixed(1) : '0.0'}
                    </td>
                    <td className="py-3 px-4 text-cyan-300">
                      {((alt.confidence || 0.85) * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={alt.status} />
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleOpenDetail(alt)}
                        className="px-2.5 py-1 text-[11px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded hover:bg-cyan-500/20 transition flex items-center space-x-1 ml-auto"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedAlert(null)}
          title={`Alert Detail Inspector: ${selectedAlert.detection_type}`}
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950 rounded border border-slate-800">
              <div>
                <span className="text-slate-500 text-[10px] block">ALERT ID</span>
                <span className="text-cyan-400 font-bold">ALT-{selectedAlert.id}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">STATUS</span>
                <StatusBadge status={selectedAlert.status} />
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">RISK SCORE</span>
                <span className="text-emerald-400 font-bold">{selectedAlert.risk_score?.toFixed(1) ?? '0.0'}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">EVIDENCE CONFIDENCE</span>
                <span className="text-cyan-300 font-bold">{((selectedAlert.confidence || 0.85) * 100).toFixed(0)}%</span>
              </div>
            </div>

            <div>
              <h4 className="text-slate-200 font-bold mb-1">Source & Target Telemetry</h4>
              <p className="text-slate-400">
                Source IP: <span className="text-cyan-400 font-bold">{selectedAlert.source_ip || '127.0.0.1'}</span> &rarr; Target: <span className="text-indigo-300 font-bold">{selectedAlert.dest_ip || 'N/A'}</span> (Port: {selectedAlert.dest_port || 'N/A'})
              </p>
            </div>

            <div>
              <h4 className="text-slate-200 font-bold mb-1">Backend Detection Explanation</h4>
              <div className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-300">
                {selectedAlert.explanation || selectedAlert.description}
              </div>
            </div>

            <div>
              <h4 className="text-slate-200 font-bold mb-1">Associated Event Evidence Streams</h4>
              {loadingEvidence ? (
                <div className="text-slate-500 py-3 text-center">Loading evidence events...</div>
              ) : evidenceEvents.length === 0 ? (
                <div className="text-slate-500 py-3 text-center border border-dashed border-slate-800 rounded">No specific evidence events retrieved.</div>
              ) : (
                <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                  {evidenceEvents.map((evt) => (
                    <div key={evt.id} className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] flex justify-between">
                      <span className="text-cyan-400 font-bold">EVT-{evt.id}: {evt.source_ip} &rarr; {evt.dest_ip}:{evt.dest_port}</span>
                      <span className="text-slate-500">[{evt.protocol}] State: {evt.connection_state}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded"
              >
                Close
              </button>
              <button
                onClick={handleStartInvestigation}
                disabled={creatingInv}
                className="px-4 py-1.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded hover:bg-emerald-500/30 flex items-center space-x-1.5 font-bold shadow-glow-success"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{creatingInv ? 'Creating Incident...' : 'Start Incident Investigation'}</span>
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
