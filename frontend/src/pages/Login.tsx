import React, { useState } from 'react';
import { Shield, Lock, User as UserIcon, Eye, EyeOff, AlertTriangle, ArrowRight } from 'lucide-react';
import { apiService } from '../services/apiService';
import { User } from '../types';

interface LoginProps {
  onLoginSuccess: (user: User) => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [identifier, setIdentifier] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier.trim() || !password) return;

    setLoading(true);
    setError(null);

    try {
      const res = await apiService.login(identifier.trim(), password);
      onLoginSuccess(res.user);
    } catch (err: any) {
      setError(err.message || "Invalid username or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4 font-mono">
      <div className="w-full max-w-md space-y-6">
        {/* Logo & Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-glow-cyan">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-wider">NETWATCH</h1>
          <p className="text-xs text-slate-400">Defensive SOC & Network Security Monitoring Platform</p>
        </div>

        {/* Login Form Panel */}
        <div className="glass-panel p-8 space-y-6 border-cyan-500/30">
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Analyst Authentication</h2>
            <p className="text-[11px] text-slate-400">Enter authorized credentials to access SOC workspace</p>
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            <div className="space-y-1.5">
              <label className="text-slate-400 block font-semibold">Username or Email</label>
              <div className="relative">
                <UserIcon className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                <input
                  type="text"
                  required
                  placeholder="admin or analyst@netwatch.local"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-slate-400 block font-semibold">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-10 py-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !identifier.trim() || !password}
              className="w-full py-3 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition font-bold flex items-center justify-center space-x-2 shadow-glow-cyan disabled:opacity-50 mt-2"
            >
              <span>{loading ? 'Authenticating Credentials...' : 'Authenticate & Access SOC'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          <div className="pt-2 text-center text-[10px] text-slate-500 border-t border-slate-800">
            Protected Defensive Security Platform • Authorization Logging Active
          </div>
        </div>
      </div>
    </div>
  );
};
