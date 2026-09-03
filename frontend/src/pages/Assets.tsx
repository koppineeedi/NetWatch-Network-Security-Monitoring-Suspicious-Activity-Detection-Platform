import React, { useState, useEffect } from 'react';
import { Server, Monitor, Shield, HardDrive, RefreshCw } from 'lucide-react';
import { Asset } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { StatusBadge } from '../components/StatusBadge';

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadAssets = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getAssets();
      setAssets(data);
    } catch (err: any) {
      setError(err.message || "Failed to load assets");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400" />
            <span>Observed Infrastructure Asset Inventory</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Observed Local Host Assets Discovered from System Telemetry
          </p>
        </div>
        <button
          onClick={loadAssets}
          className="px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Assets</span>
        </button>
      </div>

      {loading ? (
        <LoadingState message="Querying asset inventory..." />
      ) : error ? (
        <ErrorState message={error} onRetry={loadAssets} />
      ) : assets.length === 0 ? (
        <EmptyState title="No Discovered Assets" message="No host assets have been recorded in the database yet." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {assets.map((asset) => (
            <div key={asset.id} className="glass-panel p-5 space-y-3 border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-100">{asset.hostname}</span>
                <StatusBadge status={asset.status} />
              </div>
              <p className="text-cyan-400 text-xs">{asset.ip_address}</p>
              <div className="text-[10px] text-slate-500">Type: {asset.asset_type}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
