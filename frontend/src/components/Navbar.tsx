import React, { useState, useEffect } from 'react';
import { Shield, Play, Pause, Bell, Clock, Activity, Lock, LogOut, Wifi, WifiOff } from 'lucide-react';
import { User } from '../types';
import { websocketService, WsConnectionStatus } from '../services/websocketService';

interface NavbarProps {
  user: User | null;
  onLogout: () => void;
  isSimulating: boolean;
  onToggleSimulation: () => void;
  telemetryInterval: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  user,
  onLogout,
  isSimulating,
  onToggleSimulation,
  telemetryInterval
}) => {
  const [time, setTime] = useState<string>(new Date().toUTCString());
  const [wsStatus, setWsStatus] = useState<WsConnectionStatus>('OFFLINE');

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toUTCString().split(' ')[4] + ' UTC'), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (user) {
      websocketService.connect();
    } else {
      websocketService.disconnect();
    }

    const unsubscribe = websocketService.onStatusChange(setWsStatus);
    return () => {
      unsubscribe();
    };
  }, [user]);

  return (
    <header className="h-16 bg-[#0e131f]/90 backdrop-blur-md border-b border-cyan-500/20 px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
          <Shield className="w-6 h-6 animate-pulse" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-wider bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
            NETWATCH
          </h1>
          <p className="text-[10px] uppercase font-mono tracking-widest text-cyan-400/70">
            Defensive SOC Platform v1.0
          </p>
        </div>
      </div>

      {/* Center Live Telemetry & WebSocket Connection Status Bar */}
      <div className="hidden md:flex items-center space-x-4 bg-slate-900/80 px-4 py-1.5 rounded-full border border-slate-800 text-xs font-mono">
        {/* WebSocket Real-Time Connection Indicator */}
        <div className="flex items-center space-x-1.5 pr-2 border-r border-slate-700">
          <span className={`w-2.5 h-2.5 rounded-full ${
            wsStatus === 'CONNECTED' ? 'bg-emerald-400 animate-ping' :
            wsStatus === 'RECONNECTING' ? 'bg-amber-400 animate-pulse' :
            'bg-slate-500'
          }`}></span>
          <span className={
            wsStatus === 'CONNECTED' ? 'text-emerald-400 font-bold' :
            wsStatus === 'RECONNECTING' ? 'text-amber-400 font-bold' :
            'text-slate-400'
          }>
            {wsStatus === 'CONNECTED' ? 'WS LIVE' : wsStatus === 'RECONNECTING' ? 'WS RECONNECTING' : 'WS OFFLINE'}
          </span>
        </div>

        {/* Telemetry Collector Control */}
        <div className="flex items-center space-x-2">
          <span className={`w-2 h-2 rounded-full ${isSimulating ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
          <span className="text-slate-300">
            {isSimulating ? 'COLLECTOR RUNNING' : 'COLLECTOR PAUSED'}
          </span>
        </div>

        <button
          onClick={onToggleSimulation}
          className={`px-3 py-1 text-xs font-semibold rounded-full flex items-center space-x-1.5 transition ${
            isSimulating
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 hover:bg-rose-500/30'
              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
          }`}
        >
          {isSimulating ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          <span>{isSimulating ? 'Pause Collector' : 'Start Collector'}</span>
        </button>
      </div>

      {/* Right controls */}
      <div className="flex items-center space-x-4">
        <div className="hidden lg:flex items-center space-x-1 text-xs font-mono text-slate-400 bg-slate-900/60 px-3 py-1 rounded border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{time}</span>
        </div>

        {/* User Card */}
        {user ? (
          <div className="flex items-center space-x-3 border-l border-slate-800 pl-4">
            <div className="text-right hidden sm:block">
              <div className="text-xs font-semibold text-slate-200 font-mono">{user.username}</div>
              <div className="text-[10px] font-mono text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 inline-block font-bold">
                {user.role}
              </div>
            </div>
            <button
              onClick={onLogout}
              title="Logout"
              className="p-2 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="flex items-center space-x-1 text-xs text-slate-400">
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span>Unauthenticated</span>
          </div>
        )}
      </div>
    </header>
  );
};
