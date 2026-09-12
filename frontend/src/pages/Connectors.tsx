import React, { useState, useEffect } from 'react';
import { Network, Server, Cloud, RefreshCw, Play, Pause, CheckCircle, AlertTriangle, XCircle, ShieldAlert, Cpu } from 'lucide-react';
import { Connector, ConnectorTestResult } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { ErrorState } from '../components/ErrorState';

export const Connectors: React.FC = () => {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null);

  const fetchConnectors = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getConnectors();
      setConnectors(data);
    } catch (err: any) {
      setError(err.message || "Failed to load connectors");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnectors();
  }, []);

  const handleTest = async (connectorId: string) => {
    setTestingId(connectorId);
    setTestResult(null);
    try {
      const res = await apiService.testConnector(connectorId);
      setTestResult(res);
      await fetchConnectors();
    } catch (err: any) {
      setTestResult({
        connector_id: connectorId,
        status: "ERROR",
        message: err.message || "Test request failed"
      });
    } finally {
      setTestingId(null);
    }
  };

  const handleToggle = async (c: Connector) => {
    try {
      if (c.status === 'CONNECTED' || c.status === 'CONFIGURED') {
        await apiService.disableConnector(c.connector_id);
      } else {
        await apiService.enableConnector(c.connector_id);
      }
      await fetchConnectors();
    } catch (err: any) {
      alert(`Toggle failed: ${err.message}`);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'CONNECTED':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> CONNECTED</span>;
      case 'CONFIGURED':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1"><Server className="w-3 h-3" /> CONFIGURED</span>;
      case 'NOT_CONFIGURED':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> NOT CONFIGURED</span>;
      case 'ERROR':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40 flex items-center gap-1"><XCircle className="w-3 h-3" /> ERROR</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">DISABLED</span>;
    }
  };

  const getIcon = (type: string) => {
    if (type.includes('AWS') || type.includes('AZURE') || type.includes('GCP')) return <Cloud className="w-6 h-6 text-indigo-400" />;
    return <Network className="w-6 h-6 text-cyan-400" />;
  };

  if (loading) return <LoadingState message="Loading remote network & cloud connectors..." />;
  if (error) return <ErrorState message={error} onRetry={fetchConnectors} />;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <span>Enterprise Log & Cloud Connectors</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Remote UDP/TCP Syslog Receivers and AWS, Azure, GCP Infrastructure Connectors
          </p>
        </div>
        <button
          onClick={fetchConnectors}
          className="px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Connectors</span>
        </button>
      </div>

      {/* Test Result Toast */}
      {testResult && (
        <div className={`p-4 rounded-lg border font-mono ${
          testResult.status === 'CONNECTED' || testResult.status === 'CONFIGURED'
            ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-200'
            : testResult.status === 'NOT_CONFIGURED'
            ? 'bg-amber-950/60 border-amber-500/40 text-amber-200'
            : 'bg-rose-950/60 border-rose-500/40 text-rose-200'
        }`}>
          <div className="font-bold flex items-center gap-2">
            <span>Connector Test Result ({testResult.connector_id}):</span>
            <span className="uppercase font-extrabold">{testResult.status}</span>
          </div>
          <p className="mt-1 text-xs">{testResult.message}</p>
        </div>
      )}

      {/* Connectors Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {connectors.map((c) => (
          <div key={c.id} className="glass-panel p-5 space-y-4 font-mono">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center">
                  {getIcon(c.connector_type)}
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100">{c.name}</h3>
                  <div className="text-[10px] text-slate-500 font-mono">ID: {c.connector_id} | Type: {c.connector_type}</div>
                </div>
              </div>
              {getStatusBadge(c.status)}
            </div>

            <div className="p-3 rounded bg-slate-950/80 border border-slate-800 space-y-1 text-[11px]">
              <div className="flex justify-between text-slate-400">
                <span>Configured Status:</span>
                <span className="text-slate-200">{c.status}</span>
              </div>
              {c.last_seen && (
                <div className="flex justify-between text-slate-400">
                  <span>Last Seen Activity:</span>
                  <span className="text-cyan-300">{new Date(c.last_seen).toLocaleString()}</span>
                </div>
              )}
              {c.last_error && (
                <div className="text-rose-400 mt-1 text-[10px]">
                  Error: {c.last_error}
                </div>
              )}
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <button
                onClick={() => handleTest(c.connector_id)}
                disabled={testingId === c.connector_id}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 hover:text-cyan-400 rounded border border-slate-700 transition font-semibold"
              >
                {testingId === c.connector_id ? 'Testing...' : 'Test Connection'}
              </button>

              <button
                onClick={() => handleToggle(c)}
                className={`px-3 py-1.5 font-bold rounded flex items-center space-x-1.5 transition ${
                  c.status === 'CONNECTED' || c.status === 'CONFIGURED'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 hover:bg-rose-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
                }`}
              >
                {c.status === 'CONNECTED' || c.status === 'CONFIGURED' ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                <span>{c.status === 'CONNECTED' || c.status === 'CONFIGURED' ? 'Disable' : 'Enable'}</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
