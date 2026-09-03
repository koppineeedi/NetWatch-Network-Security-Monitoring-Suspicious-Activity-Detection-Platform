import React, { useState, useEffect } from 'react';
import { FileText, Upload, CheckCircle, AlertCircle, RefreshCw, HardDrive, History } from 'lucide-react';
import { apiService, LogIngestionRecord } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

export const LogAnalysis: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [lastIngestion, setLastIngestion] = useState<LogIngestionRecord | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [history, setHistory] = useState<LogIngestionRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState<boolean>(true);

  const loadHistory = async () => {
    setLoadingHistory(true);
    try {
      const records = await apiService.getLogHistory();
      setHistory(records);
    } catch {
      setHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setUploadError(null);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setUploadError(null);

    try {
      const res = await apiService.uploadLogFile(file);
      setLastIngestion(res);
      setFile(null);
      await loadHistory();
    } catch (err: any) {
      setUploadError(err.message || "File upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <span>Authorized Security Log Ingestion Pipeline</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Ingest & Normalize User-Provided Security Log Files (.log, .txt, .json, .csv)
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload Form */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100">Upload Authorized Log File</h3>

          <form onSubmit={handleUpload} className="space-y-4">
            <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500/40 rounded-lg p-6 text-center transition bg-slate-950/40">
              <Upload className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
              <p className="text-slate-300">Select log file for security normalization</p>
              <p className="text-[10px] text-slate-500 mt-1">Supported Formats: .log, .txt, .json, .csv (Max 25MB)</p>

              <input
                type="file"
                accept=".log,.txt,.json,.csv"
                onChange={handleFileChange}
                className="mt-4 text-slate-400 file:mr-4 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-mono file:bg-cyan-500/20 file:text-cyan-300 hover:file:bg-cyan-500/30"
              />
            </div>

            {file && (
              <div className="p-3 rounded bg-slate-950 border border-slate-800 flex justify-between items-center">
                <div>
                  <span className="text-cyan-300 font-bold block">{file.name}</span>
                  <span className="text-[10px] text-slate-500">{(file.size / (1024*1024)).toFixed(2)} MB</span>
                </div>
                <span className="px-2 py-0.5 text-[10px] bg-slate-800 text-slate-300 rounded">Ready</span>
              </div>
            )}

            {uploadError && (
              <div className="p-3 rounded bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
                {uploadError}
              </div>
            )}

            <button
              type="submit"
              disabled={!file || uploading}
              className="w-full py-2.5 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition font-semibold flex items-center justify-center space-x-2 disabled:opacity-50 shadow-glow-cyan"
            >
              {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
              <span>{uploading ? 'Validating & Normalizing Logs...' : 'Ingest Log File'}</span>
            </button>
          </form>
        </div>

        {/* Upload Summary / Results */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100">Latest Ingestion Summary</h3>

          {lastIngestion ? (
            <div className="space-y-3">
              <div className="p-3 rounded bg-emerald-950/40 border border-emerald-800/40 text-emerald-300 flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>Status: {lastIngestion.status} (Ingestion ID: {lastIngestion.ingestion_id})</span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">RECORDS RECEIVED</span>
                  <span className="text-slate-200 font-bold text-sm">{lastIngestion.records_received}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">RECORDS STORED</span>
                  <span className="text-emerald-400 font-bold text-sm">{lastIngestion.records_stored}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">DUPLICATE RECORDS</span>
                  <span className="text-amber-400 font-bold text-sm">{lastIngestion.records_duplicate}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">REJECTED / MALFORMED</span>
                  <span className="text-rose-400 font-bold text-sm">{lastIngestion.records_rejected}</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-slate-500 border border-dashed border-slate-800 rounded-lg">
              No recent log ingestion performed in current session.
            </div>
          )}
        </div>
      </div>

      {/* Ingestion History Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
          <History className="w-4 h-4 text-cyan-400" />
          <span>Log File Ingestion History</span>
        </h3>

        {loadingHistory ? (
          <LoadingState message="Loading log ingestion history..." />
        ) : history.length === 0 ? (
          <EmptyState title="No Log Data Ingested" message="No log file upload history recorded in the database." />
        ) : (
          <div className="glass-panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] text-slate-400 uppercase">
                    <th className="py-2.5 px-3">Ingestion ID</th>
                    <th className="py-2.5 px-3">Filename</th>
                    <th className="py-2.5 px-3">Source Tag</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Stored</th>
                    <th className="py-2.5 px-3">Duplicates</th>
                    <th className="py-2.5 px-3">Rejected</th>
                    <th className="py-2.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-slate-300">
                  {history.map((rec) => (
                    <tr key={rec.id} className="hover:bg-slate-900/60 transition">
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{rec.ingestion_id}</td>
                      <td className="py-2.5 px-3 text-slate-200">{rec.filename}</td>
                      <td className="py-2.5 px-3 text-slate-400">{rec.source}</td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px]">
                        {rec.timestamp ? new Date(rec.timestamp).toLocaleString() : 'N/A'}
                      </td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">{rec.records_stored}</td>
                      <td className="py-2.5 px-3 text-amber-400">{rec.records_duplicate}</td>
                      <td className="py-2.5 px-3 text-rose-400">{rec.records_rejected}</td>
                      <td className="py-2.5 px-3 font-semibold">{rec.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
