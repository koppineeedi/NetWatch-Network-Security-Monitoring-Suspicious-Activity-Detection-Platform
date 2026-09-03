import React from 'react';
import {
  LayoutDashboard, Activity, Network, AlertTriangle, ShieldAlert, FileSearch,
  FileText, Search, Sliders, BarChart3, Share2, GraduationCap, Settings, User, Users
} from 'lucide-react';

interface SidebarProps {
  currentPath: string;
  onNavigate: (path: string) => void;
  openAlertsCount: number;
  activeIncidentsCount: number;
  userRole?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPath,
  onNavigate,
  openAlertsCount,
  activeIncidentsCount,
  userRole
}) => {
  const baseNavItems = [
    { path: '/', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/events', label: 'Network Events', icon: Activity },
    { path: '/port-protocol', label: 'Port & Protocol', icon: Network },
    { path: '/suspicious', label: 'Suspicious Activity', icon: AlertTriangle },
    { path: '/alerts', label: 'Alerts Queue', icon: ShieldAlert, badge: openAlertsCount },
    { path: '/investigations', label: 'Investigations', icon: FileSearch, badge: activeIncidentsCount },
    { path: '/logs', label: 'Log Ingestion', icon: FileText },
    { path: '/ip-analysis', label: 'IP Investigation', icon: Search },
    { path: '/rules', label: 'Detection Rules', icon: Sliders },
    { path: '/reports', label: 'SOC Reports', icon: BarChart3 },
    { path: '/topology', label: 'Network Topology', icon: Share2 },
    { path: '/training', label: 'SOC Training', icon: GraduationCap },
    { path: '/settings', label: 'System Settings', icon: Settings },
  ];

  if (userRole === 'ADMIN') {
    baseNavItems.push({ path: '/users', label: 'User Management', icon: Users });
  }

  return (
    <aside className="w-64 bg-[#090d16] border-r border-slate-800/80 flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="py-4 px-3 space-y-1">
        <div className="px-3 pb-2 text-[11px] font-mono uppercase tracking-wider text-slate-500">
          SOC Operations
        </div>
        {baseNavItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPath === item.path;

          return (
            <button
              key={item.path}
              onClick={() => onNavigate(item.path)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full ${
                  isActive ? 'bg-rose-500 text-white' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                }`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Role Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40">
        <div className="flex items-center space-x-2 text-xs text-slate-400">
          <User className="w-4 h-4 text-cyan-400" />
          <span className="truncate">Active Role:</span>
          <span className="text-cyan-300 font-mono font-semibold">{userRole || 'ANALYST'}</span>
        </div>
      </div>
    </aside>
  );
};
