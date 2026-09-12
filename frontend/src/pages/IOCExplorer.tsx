import React, { useState, useEffect } from 'react';
import { Search, Filter, RefreshCw, Upload, Plus, Trash2, Database, ShieldAlert } from 'lucide-react';
import { IOC } from '../types';
import { apiService } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';
import { SeverityBadge } from '../components/SeverityBadge';
import { Modal } from '../components/Modal';

export const IOCExplorer: React.FC = () => {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadResult, setUploadResult] = useState<any | null>(null);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newVal, setNewVal] = useState('');
  const [newType, setNewType] = useState('IP');
  const [newConf, setNewConf] = useState(80);
  const [newSev, setNewSev] = useState('HIGH');
  const [creating, setCreating] = useState(false);

  const fetchIOCs = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getIOCs(searchTerm, typeFilter, 'ALL', severityFilter);
      setIocs(data);
    } catch (err: any) {
      setError(err.message || "Failed to load IOC database records");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIOCs();
  }, [searchTerm, typeFilter, severityFilter]);

  const handleDelete = async (id: number) => {
    if (!confirm("Are you sure you want to delete this IOC record?")) return;
    try {
      await apiService.deleteIOC(id);
      await fetchIOCs();
    } catch (err: any) {
      alert(`Failed to delete IOC: ${err.message}`);
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;
    setUploading(true);
    setUploadResult(null);
    try {
      const res = await apiService.uploadIOCFeed(selectedFile);
      setUploadResult(res);
      await fetchIOCs();
    } catch (err: any) {
      alert(`IOC Feed upload failed: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVal) return;
    setCreating(true);
    try {
      await apiService.createIOC({
        ioc_value: newVal,
        ioc_type: newType,
        confidence: newConf,
        severity: newSev,
        source: "MANUAL_INPUT"
      });
      setShowCreateModal(false);
      setNewVal('');
      await fetchIOCs();
    } catch (err: any) {
      alert(`Create IOC failed: ${err.message}`);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            <span>IOC Explorer & Feed Ingestion</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Indicators of Compromise Database (IPs, Domains, Hashes, URLs)
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setShowUploadModal(true)}
            className="px-3 py-1.5 text-xs bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 rounded-lg hover:bg-indigo-500/30 transition flex items-center space-x-1.5 font-bold"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload IOC Feed</span>
          </button>

          <button
            onClick={() => setShowCreateModal(true)}
            className="px-3 py-1.5 text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-lg hover:bg-emerald-500/30 transition flex items-center space-x-1.5 font-bold"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add IOC</span>
          </button>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div className="glass-panel p-4 flex flex-col md:flex-row items-center gap-4 justify-between">
        {/* Search */}
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search IOC value or tags..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          <div className="flex items-center space-x-2 text-slate-400">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Filters:</span>
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All IOC Types</option>
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain</option>
            <option value="HASH_MD5">MD5 Hash</option>
            <option value="HASH_SHA256">SHA256 Hash</option>
            <option value="URL">URL</option>
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

      {/* Main Table Content */}
      {loading ? (
        <LoadingState message="Loading IOC records..." />
      ) : error ? (
        <ErrorState message={error} onRetry={fetchIOCs} />
      ) : iocs.length === 0 ? (
        <EmptyState title="No IOC records stored." message="Click 'Upload IOC Feed' or 'Add IOC' above to import threat indicators." />
      ) : (
        <div className="glass-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase tracking-wider">
                  <th className="py-3 px-4">IOC Value</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Source Feed</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">First Seen</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs text-slate-300">
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-900/60 transition">
                    <td className="py-3 px-4 font-bold text-cyan-400">
                      {ioc.ioc_value}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-300 border border-slate-700">
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {ioc.source}
                    </td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={ioc.severity} />
                    </td>
                    <td className="py-3 px-4 text-emerald-400 font-bold">
                      {ioc.confidence}%
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleDelete(ioc.id)}
                        className="p-1.5 text-rose-400 hover:bg-rose-500/20 rounded transition ml-auto"
                        title="Delete IOC"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      {showUploadModal && (
        <Modal isOpen={true} onClose={() => setShowUploadModal(false)} title="Import Threat Intelligence IOC Feed">
          <form onSubmit={handleUploadSubmit} className="space-y-4 text-xs font-mono">
            <p className="text-slate-400">
              Upload authorized IOC list file (.txt, .json, .csv). Each record will be validated, normalized, and deduplicated before storing.
            </p>

            <input
              type="file"
              accept=".txt,.json,.csv,.log"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-slate-300"
            />

            {uploadResult && (
              <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded text-emerald-200">
                <div className="font-bold">Feed Import Complete!</div>
                <div>Received: {uploadResult.records_received} | Accepted: {uploadResult.records_accepted} | Rejected: {uploadResult.records_rejected}</div>
              </div>
            )}

            <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
              <button type="button" onClick={() => setShowUploadModal(false)} className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded">
                Close
              </button>
              <button
                type="submit"
                disabled={!selectedFile || uploading}
                className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded disabled:opacity-50"
              >
                {uploading ? 'Processing...' : 'Upload & Process Feed'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <Modal isOpen={true} onClose={() => setShowCreateModal(false)} title="Manually Register Indicator of Compromise">
          <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs font-mono">
            <div>
              <label className="block text-slate-400 mb-1">IOC Value (IP, Domain, Hash)</label>
              <input
                type="text"
                placeholder="e.g. 192.168.1.100 or malicious.com or md5hash"
                value={newVal}
                onChange={(e) => setNewVal(e.target.value)}
                className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-slate-200"
              />
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-slate-400 mb-1">Type</label>
                <select value={newType} onChange={(e) => setNewType(e.target.value)} className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-slate-200">
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="HASH_MD5">MD5 Hash</option>
                  <option value="HASH_SHA256">SHA256 Hash</option>
                  <option value="URL">URL</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Confidence (%)</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={newConf}
                  onChange={(e) => setNewConf(parseInt(e.target.value) || 50)}
                  className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Severity</label>
                <select value={newSev} onChange={(e) => setNewSev(e.target.value)} className="w-full p-2 bg-slate-950 border border-slate-800 rounded text-slate-200">
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
              <button type="button" onClick={() => setShowCreateModal(false)} className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded">
                Cancel
              </button>
              <button type="submit" disabled={creating || !newVal} className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded disabled:opacity-50">
                {creating ? 'Creating...' : 'Save IOC Record'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};
