import React from 'react';
import { Settings, Cpu, HardDrive, Database, Sliders, CheckCircle } from 'lucide-react';

interface SystemSettingsProps {
  telemetryInterval: number;
  onIntervalChange: (interval: number) => void;
}

export const SystemSettings: React.FC<SystemSettingsProps> = ({
  telemetryInterval,
  onIntervalChange
}) => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          <span>System Settings & Telemetry Controls</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Telemetry Simulation Stream Parameters, Ingestion Engines & Backend Health Diagnostics
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Telemetry Speed & Thermal Protection */}
        <div className="glass-panel p-6 space-y-5 border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center space-x-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span>Telemetry Simulation Generator Rate</span>
          </h3>

          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-300">Packet Injection Interval:</span>
              <span className="text-cyan-400 font-bold text-sm">{telemetryInterval} Seconds</span>
            </div>

            <input
              type="range"
              min={1}
              max={5}
              step={1}
              value={telemetryInterval}
              onChange={(e) => onIntervalChange(parseInt(e.target.value))}
              className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />

            <div className="flex justify-between text-[10px] text-slate-500">
              <span>1s (High Speed)</span>
              <span>3s (Balanced)</span>
              <span>5s (Thermal Safe 16GB RAM)</span>
            </div>

            <p className="text-[11px] text-slate-400 pt-1 leading-normal">
              Note: Configured for thermal safety and memory efficiency on standard developer laptops (16GB RAM constraint).
            </p>
          </div>

          {/* Integration Flags */}
          <div className="space-y-3 font-mono text-xs">
            <span className="text-slate-400 block font-semibold">Ingestion Engine Connectors:</span>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span className="text-slate-200">Zeek NSM Network Telemetry Agent</span>
              </div>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/40">ENABLED</span>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span className="text-slate-200">Suricata IDS / IPS Alert Parser</span>
              </div>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/40">ENABLED</span>
            </div>
          </div>
        </div>

        {/* Backend & REST Endpoint Diagnostics */}
        <div className="glass-panel p-6 space-y-5 border-slate-800 font-mono text-xs">
          <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Backend REST API Diagnostics</span>
          </h3>

          <div className="space-y-3">
            <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">REST API SERVER ENDPOINT</span>
              <span className="text-cyan-400">http://localhost:8000/api</span>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">DATABASE BACKEND</span>
              <span className="text-emerald-400">PostgreSQL (Auto SQLite Fallback active: netwatch.db)</span>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">PYDANTIC V2 SCHEMA VALIDATOR</span>
              <span className="text-slate-200">Strict Typing Enabled</span>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-500 block">AUTHENTICATION SCHEME</span>
              <span className="text-slate-200">Pre-seeded RBAC Tokens (Analyst, Manager, Admin)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
