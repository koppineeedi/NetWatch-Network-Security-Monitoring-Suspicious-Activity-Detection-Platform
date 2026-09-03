import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { User } from './types';
import { apiService } from './services/apiService';

// Pages
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { NetworkEvents } from './pages/NetworkEvents';
import { Alerts } from './pages/Alerts';
import { Investigations } from './pages/Investigations';
import { LogAnalysis } from './pages/LogAnalysis';
import { IPAnalysis } from './pages/IPAnalysis';
import { DetectionRules } from './pages/DetectionRules';
import { Assets } from './pages/Assets';
import { Reports } from './pages/Reports';
import { TrainingSimulator } from './pages/TrainingSimulator';
import { SystemSettings } from './pages/SystemSettings';
import { UserManagement } from './pages/UserManagement';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(() => {
    try {
      const savedUser = localStorage.getItem('netwatch_user');
      const savedToken = localStorage.getItem('netwatch_token');
      if (savedUser && savedToken) {
        return JSON.parse(savedUser);
      }
    } catch {}
    return null;
  });

  const [authChecking, setAuthChecking] = useState<boolean>(true);
  const [currentPath, setCurrentPath] = useState<string>('/');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [telemetryInterval, setTelemetryInterval] = useState<number>(10);

  useEffect(() => {
    const verifyAuth = async () => {
      const token = localStorage.getItem('netwatch_token');
      if (token) {
        try {
          const user = await apiService.getMe();
          setCurrentUser(user);
          localStorage.setItem('netwatch_user', JSON.stringify(user));
        } catch {
          setCurrentUser(null);
          localStorage.removeItem('netwatch_token');
          localStorage.removeItem('netwatch_user');
        }
      } else {
        setCurrentUser(null);
      }
      setAuthChecking(false);
    };

    verifyAuth();

    const handleAuthExpired = () => {
      setCurrentUser(null);
    };

    window.addEventListener('netwatch_auth_expired', handleAuthExpired);
    return () => window.removeEventListener('netwatch_auth_expired', handleAuthExpired);
  }, []);

  const handleLogout = async () => {
    await apiService.logout();
    setCurrentUser(null);
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-slate-950 text-cyan-400 font-mono flex items-center justify-center">
        <span>Authenticating Session...</span>
      </div>
    );
  }

  if (!currentUser) {
    return <Login onLoginSuccess={(user) => setCurrentUser(user)} />;
  }

  const renderView = () => {
    switch (currentPath) {
      case '/':
        return <Dashboard onNavigate={setCurrentPath} />;
      case '/events':
        return <NetworkEvents />;
      case '/alerts':
        return <Alerts />;
      case '/investigations':
        return <Investigations currentUser={currentUser.username} />;
      case '/logs':
        return <LogAnalysis />;
      case '/ip-analysis':
        return <IPAnalysis />;
      case '/rules':
        return <DetectionRules userRole={currentUser.role} />;
      case '/assets':
        return <Assets />;
      case '/reports':
        return <Reports events={[]} alerts={[]} />;
      case '/training':
        return <TrainingSimulator />;
      case '/settings':
        return <SystemSettings telemetryInterval={telemetryInterval} onIntervalChange={setTelemetryInterval} />;
      case '/users':
        return currentUser.role === 'ADMIN' ? <UserManagement /> : <Dashboard onNavigate={setCurrentPath} />;
      default:
        return <Dashboard onNavigate={setCurrentPath} />;
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#07090e] text-slate-100 font-sans">
      <Navbar
        user={currentUser}
        onLogout={handleLogout}
        isSimulating={isSimulating}
        onToggleSimulation={() => setIsSimulating(!isSimulating)}
        telemetryInterval={telemetryInterval}
      />

      <div className="flex flex-1">
        <Sidebar
          currentPath={currentPath}
          onNavigate={setCurrentPath}
          openAlertsCount={0}
          activeIncidentsCount={0}
          userRole={currentUser.role}
        />

        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {renderView()}
        </main>
      </div>
    </div>
  );
};
