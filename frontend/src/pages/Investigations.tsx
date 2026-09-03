import React, { useState, useEffect } from 'react';
import { Briefcase, MessageSquare, Clock, CheckCircle, ShieldAlert, Plus, RefreshCw, Send } from 'lucide-react';
import { Investigation, AnalystNote } from '../types';
import { apiService, TimelineEntry } from '../services/apiService';
import { LoadingState } from '../components/LoadingState';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

interface InvestigationsProps {
  investigations?: Investigation[];
  onAddNote?: (invId: number, noteText: string) => void;
  currentUser?: string;
}

export const Investigations: React.FC<InvestigationsProps> = ({
  currentUser = 'SOC Analyst'
}) => {
  const [cases, setCases] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedCase, setSelectedCase] = useState<Investigation | null>(null);
  const [newNoteText, setNewNoteText] = useState<string>('');
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);

  const [verdict, setVerdict] = useState<string>('TRUE_POSITIVE');
  const [verdictReason, setVerdictReason] = useState<string>('');
  const [submittingVerdict, setSubmittingVerdict] = useState<boolean>(false);

  const fetchCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getInvestigations();
      setCases(data);
      if (selectedCase) {
        const updated = data.find(c => c.id === selectedCase.id);
        if (updated) setSelectedCase(updated);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load investigations");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleSelectCase = async (inv: Investigation) => {
    setSelectedCase(inv);
    setLoadingTimeline(true);
    try {
      const tl = await apiService.getInvestigationTimeline(inv.id);
      setTimeline(tl);
    } catch {
      setTimeline([]);
    } finally {
      setLoadingTimeline(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNoteText.trim()) return;

    try {
      await apiService.addAnalystNote(selectedCase.id, currentUser, newNoteText);
      setNewNoteText('');
      await fetchCases();
      if (selectedCase) handleSelectCase(selectedCase);
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    }
  };

  const handleRecordVerdict = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase) return;

    setSubmittingVerdict(true);
    try {
      await apiService.updateInvestigation(
        selectedCase.id,
        "RESOLVED",
        verdict,
        verdictReason,
        currentUser
      );
      setVerdictReason('');
      await fetchCases();
      if (selectedCase) handleSelectCase(selectedCase);
    } catch (err: any) {
      alert(`Failed to submit verdict: ${err.message}`);
    } finally {
      setSubmittingVerdict(false);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Briefcase className="w-5 h-5 text-cyan-400" />
            <span>SOC Incident Case Management & Investigation Workspace</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative Case Triage, Analyst Notes, Chronological Timeline & Resolution Verdicts
          </p>
        </div>
        <button
          onClick={fetchCases}
          className="px-3 py-1.5 text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/20 transition flex items-center space-x-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Cases</span>
        </button>
      </div>

      {loading ? (
        <LoadingState message="Loading incident investigation cases..." />
      ) : error ? (
        <ErrorState message={error} onRetry={fetchCases} />
      ) : cases.length === 0 ? (
        <EmptyState title="No active investigations" message="No open incident investigation cases in database." />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Cases List */}
          <div className="space-y-3 lg:col-span-1">
            <h3 className="text-sm font-bold text-slate-100 font-mono">Active Case Files ({cases.length})</h3>
            <div className="space-y-2 max-h-[650px] overflow-y-auto pr-1">
              {cases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => handleSelectCase(c)}
                  className={`p-4 rounded-lg glass-panel cursor-pointer transition border ${
                    selectedCase?.id === c.id ? 'border-cyan-500 bg-slate-900/80 shadow-glow-cyan' : 'border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-cyan-400 font-bold">{c.case_number}</span>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                      c.status === 'RESOLVED' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' :
                      c.status === 'OPEN' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                      'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    }`}>
                      {c.status}
                    </span>
                  </div>

                  <h4 className="text-slate-100 font-semibold mt-2">{c.title}</h4>
                  <p className="text-slate-400 text-[11px] mt-1 line-clamp-2">{c.summary}</p>

                  <div className="text-[10px] text-slate-500 mt-2 flex justify-between">
                    <span>Analyst: {c.assigned_analyst}</span>
                    <span>{new Date(c.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Case Detail Workspace */}
          {selectedCase ? (
            <div className="lg:col-span-2 space-y-6">
              <div className="glass-panel p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="text-base font-bold text-slate-100">{selectedCase.case_number}: {selectedCase.title}</h3>
                    <p className="text-xs text-slate-400">Assigned Analyst: <span className="text-cyan-300">{selectedCase.assigned_analyst}</span> | Status: <span className="text-emerald-400 font-bold">{selectedCase.status}</span></p>
                  </div>
                  {selectedCase.verdict && (
                    <span className="px-3 py-1 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded font-bold">
                      VERDICT: {selectedCase.verdict}
                    </span>
                  )}
                </div>

                {/* Case Summary */}
                <div>
                  <h4 className="text-slate-300 font-bold mb-1">Executive Summary</h4>
                  <p className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-300">{selectedCase.summary}</p>
                </div>

                {/* Chronological Timeline */}
                <div>
                  <h4 className="text-slate-300 font-bold mb-2 flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-cyan-400" />
                    <span>Real Incident Timeline</span>
                  </h4>
                  {loadingTimeline ? (
                    <div className="text-slate-500 py-3">Loading timeline...</div>
                  ) : (
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {timeline.map((item, idx) => (
                        <div key={idx} className="p-2 bg-slate-950 rounded border border-slate-800 flex flex-col space-y-0.5">
                          <div className="flex justify-between text-[10px] text-slate-500">
                            <span className="text-cyan-400 font-bold">{item.event_type}</span>
                            <span>{new Date(item.timestamp).toLocaleString()}</span>
                          </div>
                          <span className="text-slate-200 font-semibold">{item.title}</span>
                          <span className="text-slate-400 text-[11px]">{item.details}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Analyst Notes Section */}
                <div>
                  <h4 className="text-slate-300 font-bold mb-2 flex items-center gap-1.5">
                    <MessageSquare className="w-4 h-4 text-cyan-400" />
                    <span>Persistent Analyst Notes ({selectedCase.notes?.length || 0})</span>
                  </h4>

                  <div className="space-y-2 max-h-40 overflow-y-auto mb-3 pr-1">
                    {selectedCase.notes?.map((n) => (
                      <div key={n.id} className="p-2.5 bg-slate-950 rounded border border-slate-800">
                        <div className="flex justify-between text-[10px] text-slate-500">
                          <span className="text-cyan-300 font-bold">{n.author}</span>
                          <span>{new Date(n.timestamp).toLocaleString()}</span>
                        </div>
                        <p className="text-slate-300 mt-1">{n.note_text}</p>
                      </div>
                    ))}
                  </div>

                  <form onSubmit={handleAddNote} className="flex space-x-2">
                    <input
                      type="text"
                      placeholder="Add investigation note or evidence update..."
                      value={newNoteText}
                      onChange={(e) => setNewNoteText(e.target.value)}
                      className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="submit"
                      disabled={!newNoteText.trim()}
                      className="px-4 py-2 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded hover:bg-cyan-500/30 flex items-center space-x-1 disabled:opacity-50"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Post Note</span>
                    </button>
                  </form>
                </div>

                {/* Verdict & Resolution Form */}
                <div className="p-4 bg-slate-950 rounded border border-slate-800 space-y-3 pt-3">
                  <h4 className="text-slate-200 font-bold">Analyst Incident Resolution & Verdict</h4>
                  <form onSubmit={handleRecordVerdict} className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-slate-400 block mb-1">Select Verdict</label>
                        <select
                          value={verdict}
                          onChange={(e) => setVerdict(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-slate-200"
                        >
                          <option value="TRUE_POSITIVE">TRUE POSITIVE (Confirmed Security Issue)</option>
                          <option value="FALSE_POSITIVE">FALSE POSITIVE (Authorized / Benign Activity)</option>
                          <option value="BENIGN">BENIGN (Expected Baseline Telemetry)</option>
                          <option value="INCONCLUSIVE">INCONCLUSIVE (Insufficient Logs)</option>
                        </select>
                      </div>

                      <div>
                        <label className="text-slate-400 block mb-1">Resolution Summary</label>
                        <input
                          type="text"
                          required
                          placeholder="Provide analyst justification for resolution..."
                          value={verdictReason}
                          onChange={(e) => setVerdictReason(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-slate-200"
                        />
                      </div>
                    </div>

                    <button
                      type="submit"
                      disabled={submittingVerdict || !verdictReason.trim()}
                      className="w-full py-2 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded hover:bg-emerald-500/30 font-bold transition disabled:opacity-50"
                    >
                      {submittingVerdict ? 'Recording Resolution...' : 'Submit Final Verdict & Resolve Case'}
                    </button>
                  </form>
                </div>
              </div>
            </div>
          ) : (
            <div className="lg:col-span-2 glass-panel p-8 flex items-center justify-center text-slate-500">
              Select an investigation case file on the left to view workspace details.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
