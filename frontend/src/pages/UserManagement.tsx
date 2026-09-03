import React, { useState, useEffect } from 'react';
import { Users, UserPlus, Shield, Check, X, RefreshCw, Key, AlertTriangle } from 'lucide-react';
import { User, UserRole } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { ErrorState } from '../components/ErrorState';
import { Modal } from '../components/Modal';

export const UserManagement: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>('');
  const [newEmail, setNewEmail] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [newRole, setNewRole] = useState<UserRole>('ANALYST');
  const [creating, setCreating] = useState<boolean>(false);

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getUsers();
      setUsers(data);
    } catch (err: any) {
      setError(err.message || "Failed to load user accounts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newEmail.trim() || !newPassword) return;

    setCreating(true);
    try {
      await apiService.createUser({
        username: newUsername.trim(),
        email: newEmail.trim(),
        password: newPassword,
        role: newRole
      });
      setShowCreateModal(false);
      setNewUsername('');
      setNewEmail('');
      setNewPassword('');
      setNewRole('ANALYST');
      await fetchUsers();
    } catch (err: any) {
      alert(`Failed to create user: ${err.message}`);
    } finally {
      setCreating(false);
    }
  };

  const handleRoleChange = async (userId: number, role: UserRole) => {
    try {
      await apiService.updateUserRole(userId, role);
      await fetchUsers();
    } catch (err: any) {
      alert(`Role update failed: ${err.message}`);
    }
  };

  const handleStatusToggle = async (userId: number, currentActive: boolean) => {
    try {
      await apiService.updateUserStatus(userId, !currentActive);
      await fetchUsers();
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Users className="w-5 h-5 text-cyan-400" />
            <span>SOC User Account & RBAC Authorization Management</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Admin-Only User Provisioning, Role Assignments, and Access Status Controls
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-3 py-1.5 text-xs bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition flex items-center space-x-1.5 font-bold shadow-glow-cyan"
          >
            <UserPlus className="w-3.5 h-3.5" />
            <span>Create User Account</span>
          </button>
          <button
            onClick={fetchUsers}
            className="px-3 py-1.5 text-xs bg-slate-800 text-slate-300 rounded-lg hover:bg-slate-700 transition flex items-center space-x-1"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {loading ? (
        <LoadingState message="Loading user accounts list..." />
      ) : error ? (
        <ErrorState message={error} onRetry={fetchUsers} />
      ) : (
        <div className="glass-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase">
                  <th className="py-3 px-4">User ID</th>
                  <th className="py-3 px-4">Username</th>
                  <th className="py-3 px-4">Email</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created Date</th>
                  <th className="py-3 px-4">Last Login</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-slate-300">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-900/60 transition">
                    <td className="py-3 px-4 text-cyan-400 font-bold">USR-{u.id}</td>
                    <td className="py-3 px-4 font-semibold text-slate-100">{u.username}</td>
                    <td className="py-3 px-4 text-slate-400">{u.email}</td>
                    <td className="py-3 px-4">
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value as UserRole)}
                        className={`bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs font-bold ${
                          u.role === 'ADMIN' ? 'text-amber-400 border-amber-500/40' :
                          u.role === 'ANALYST' ? 'text-cyan-400 border-cyan-500/40' :
                          'text-slate-400'
                        }`}
                      >
                        <option value="ADMIN">ADMIN</option>
                        <option value="ANALYST">ANALYST</option>
                        <option value="VIEWER">VIEWER</option>
                      </select>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                        u.is_active ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      }`}>
                        {u.is_active ? 'ACTIVE' : 'DISABLED'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleStatusToggle(u.id, u.is_active)}
                        className={`px-2.5 py-1 text-[11px] rounded border transition ${
                          u.is_active ? 'bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                        }`}
                      >
                        {u.is_active ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create User Modal */}
      {showCreateModal && (
        <Modal
          isOpen={true}
          onClose={() => setShowCreateModal(false)}
          title="Provision New SOC User Account"
        >
          <form onSubmit={handleCreateUser} className="space-y-4 font-mono text-xs">
            <div className="space-y-1">
              <label className="text-slate-400 block font-semibold">Username</label>
              <input
                type="text"
                required
                placeholder="johndoe"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-400 block font-semibold">Email Address</label>
              <input
                type="email"
                required
                placeholder="johndoe@netwatch.local"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-400 block font-semibold">Initial Password (min 8 characters)</label>
              <input
                type="password"
                required
                minLength={8}
                placeholder="••••••••••••"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="space-y-1">
              <label className="text-slate-400 block font-semibold">Assign System Role</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-bold"
              >
                <option value="ANALYST">ANALYST (Triage, Investigations, Rules Read)</option>
                <option value="ADMIN">ADMIN (Full System Controls & User Management)</option>
                <option value="VIEWER">VIEWER (Read-Only SOC Visibility)</option>
              </select>
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={creating || !newUsername.trim() || !newEmail.trim() || newPassword.length < 8}
                className="px-4 py-1.5 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded hover:bg-cyan-500/30 font-bold shadow-glow-cyan disabled:opacity-50"
              >
                {creating ? 'Creating User...' : 'Provision User'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
