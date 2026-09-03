import React, { useState } from 'react';
import { Share2, Shield, HardDrive, Server, Monitor, Globe, AlertTriangle, CheckCircle } from 'lucide-react';
import { Asset } from '../types';

interface NetworkTopologyProps {
  assets: Asset[];
}

export const NetworkTopology: React.FC<NetworkTopologyProps> = ({ assets }) => {
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(
    assets.length > 0 ? assets[0] : null
  );

  const getAssetIcon = (type: string) => {
    switch (type) {
      case 'FIREWALL':
        return Shield;
      case 'CORE_SWITCH':
        return HardDrive;
      case 'WEB_SERVER':
      case 'DB_SERVER':
      case 'DOMAIN_CONTROLLER':
        return Server;
      default:
        return Monitor;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Share2 className="w-5 h-5 text-cyan-400" />
          <span>Interactive Infrastructure Network Topology Diagram</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Visual Segment Map: Internet Perimeter &rarr; Gateway Firewall &rarr; Core Switch &rarr; Enterprise Nodes
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Diagram Area */}
        <div className="lg:col-span-2 glass-panel p-6 space-y-8 flex flex-col items-center justify-center min-h-[480px]">
          {/* Internet Edge Node */}
          <div className="flex flex-col items-center">
            <div className="w-14 h-14 rounded-full bg-indigo-500/10 border-2 border-indigo-500/40 flex items-center justify-center text-indigo-400 shadow-[0_0_15px_rgba(99,102,241,0.2)]">
              <Globe className="w-7 h-7" />
            </div>
            <span className="text-xs font-mono font-bold text-indigo-300 mt-1">WAN / Internet</span>
          </div>

          <div className="w-0.5 h-8 bg-gradient-to-b from-indigo-500 to-cyan-500"></div>

          {/* Firewall Node */}
          {assets.filter(a => a.asset_type === 'FIREWALL').map((fw) => {
            const Icon = getAssetIcon(fw.asset_type);
            const isSelected = selectedAsset?.id === fw.id;
            return (
              <div
                key={fw.id}
                onClick={() => setSelectedAsset(fw)}
                className={`p-4 rounded-xl border flex items-center space-x-3 cursor-pointer transition ${
                  isSelected ? 'bg-cyan-950/60 border-cyan-500 shadow-glow-cyan' : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Icon className="w-5 h-5" />
                </div>
                <div className="font-mono">
                  <div className="text-xs font-bold text-slate-100">{fw.hostname}</div>
                  <div className="text-[10px] text-cyan-400">{fw.ip_address}</div>
                </div>
              </div>
            );
          })}

          <div className="w-0.5 h-8 bg-cyan-500"></div>

          {/* Core Switch Node */}
          {assets.filter(a => a.asset_type === 'CORE_SWITCH').map((sw) => {
            const Icon = getAssetIcon(sw.asset_type);
            const isSelected = selectedAsset?.id === sw.id;
            return (
              <div
                key={sw.id}
                onClick={() => setSelectedAsset(sw)}
                className={`p-4 rounded-xl border flex items-center space-x-3 cursor-pointer transition ${
                  isSelected ? 'bg-cyan-950/60 border-cyan-500 shadow-glow-cyan' : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Icon className="w-5 h-5" />
                </div>
                <div className="font-mono">
                  <div className="text-xs font-bold text-slate-100">{sw.hostname}</div>
                  <div className="text-[10px] text-cyan-400">{sw.ip_address}</div>
                </div>
              </div>
            );
          })}

          <div className="w-full max-w-lg h-0.5 bg-slate-800 my-2"></div>

          {/* Subnet Nodes Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 w-full">
            {assets.filter(a => a.asset_type !== 'FIREWALL' && a.asset_type !== 'CORE_SWITCH').map((asset) => {
              const Icon = getAssetIcon(asset.asset_type);
              const isSelected = selectedAsset?.id === asset.id;
              const isCritical = asset.status === 'CRITICAL' || asset.risk_score > 70;
              const isWarning = asset.status === 'WARNING' || asset.risk_score > 40;

              return (
                <div
                  key={asset.id}
                  onClick={() => setSelectedAsset(asset)}
                  className={`p-3 rounded-lg border flex flex-col items-center text-center cursor-pointer transition ${
                    isSelected ? 'bg-cyan-950/60 border-cyan-500 shadow-glow-cyan' :
                    isCritical ? 'bg-rose-950/20 border-rose-500/50' :
                    isWarning ? 'bg-amber-950/20 border-amber-500/50' :
                    'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-2 ${
                    isCritical ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse' :
                    isWarning ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                    'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-mono font-bold text-slate-200 truncate w-full">{asset.hostname}</span>
                  <span className="text-[10px] font-mono text-cyan-400">{asset.ip_address}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Drawer: Asset Details */}
        {selectedAsset ? (
          <div className="glass-panel p-6 space-y-5 border-cyan-500/30 font-mono text-xs">
            <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">{selectedAsset.hostname}</h3>
                <p className="text-[11px] text-cyan-400">{selectedAsset.ip_address}</p>
              </div>
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                selectedAsset.status === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                selectedAsset.status === 'WARNING' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}>
                {selectedAsset.status}
              </span>
            </div>

            <div className="space-y-3">
              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">ASSET CATEGORY</span>
                <span className="text-slate-200 font-bold">{selectedAsset.asset_type}</span>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">EXPLAINABLE RISK SCORE</span>
                <div className="flex items-center space-x-2">
                  <span className={`text-lg font-bold ${selectedAsset.risk_score > 70 ? 'text-rose-400' : 'text-slate-200'}`}>
                    {selectedAsset.risk_score.toFixed(0)} / 100
                  </span>
                  <span className="text-slate-400">({selectedAsset.risk_level} Risk)</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-center">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">TOTAL EVENTS</span>
                  <span className="text-cyan-400 font-bold">{selectedAsset.events_count || 1420}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">ACTIVE ALERTS</span>
                  <span className="text-rose-400 font-bold">{selectedAsset.alerts_count || 3}</span>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">DESCRIPTION & ROLE</span>
                <p className="text-slate-300 leading-normal">{selectedAsset.description || 'Enterprise Infrastructure Node'}</p>
              </div>
            </div>
          </div>
        ) : (
          <div className="glass-panel p-8 text-center text-slate-500 font-mono text-xs">
            Select a network topology node to inspect details.
          </div>
        )}
      </div>
    </div>
  );
};
