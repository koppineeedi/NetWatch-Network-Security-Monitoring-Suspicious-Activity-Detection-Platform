import React, { useState } from 'react';
import { GraduationCap, BookOpen, HelpCircle, CheckCircle, XCircle, Lightbulb, Award, ArrowRight } from 'lucide-react';
import { mockTrainingScenarios } from '../data/mockData';
import { TrainingScenario } from '../types';

export const TrainingSimulator: React.FC = () => {
  const [activeScenarioId, setActiveScenarioId] = useState(mockTrainingScenarios[0].id);
  const [userAnswers, setUserAnswers] = useState<Record<string, number>>({});
  const [showHints, setShowHints] = useState<Record<string, boolean>>({});
  const [submitted, setSubmitted] = useState<Record<string, boolean>>({});

  const scenario = mockTrainingScenarios.find(s => s.id === activeScenarioId) || mockTrainingScenarios[0];

  const handleSelectOption = (qId: number, optionIdx: number) => {
    if (submitted[scenario.id]) return;
    setUserAnswers(prev => ({ ...prev, [`${scenario.id}_${qId}`]: optionIdx }));
  };

  const handleToggleHint = (qId: number) => {
    setShowHints(prev => ({ ...prev, [`${scenario.id}_${qId}`]: !prev[`${scenario.id}_${qId}`] }));
  };

  const handleSubmitScenario = () => {
    setSubmitted(prev => ({ ...prev, [scenario.id]: true }));
  };

  // Calculate user score
  const calculateScore = (scen: TrainingScenario) => {
    let correct = 0;
    scen.questions.forEach(q => {
      if (userAnswers[`${scen.id}_${q.id}`] === q.correctIndex) {
        correct++;
      }
    });
    return { correct, total: scen.questions.length };
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 glass-panel border-cyan-500/30">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <GraduationCap className="w-5 h-5 text-cyan-400" />
          <span>SOC Analyst Interactive Training Simulator</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          5 Educational Defensive Scenarios with Interactive Telemetry Analysis, Hints & Explanations
        </p>
      </div>

      {/* Scenario Selector Pills */}
      <div className="flex flex-wrap items-center gap-3">
        {mockTrainingScenarios.map((scen, index) => {
          const isActive = scen.id === activeScenarioId;
          const isDone = submitted[scen.id];
          return (
            <button
              key={scen.id}
              onClick={() => setActiveScenarioId(scen.id)}
              className={`px-4 py-2.5 rounded-lg text-xs font-mono font-semibold transition flex items-center space-x-2 ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-glow-cyan'
                  : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:border-slate-700'
              }`}
            >
              <span>Scenario {index + 1}</span>
              {isDone && <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
            </button>
          );
        })}
      </div>

      {/* Main Scenario Desk */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Log Telemetry & Context */}
        <div className="glass-panel p-5 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="px-2 py-0.5 text-[10px] font-bold bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/40">
              {scenario.category}
            </span>
            <span className="text-[10px] text-amber-400 font-bold">{scenario.difficulty} Level</span>
          </div>

          <h3 className="text-sm font-bold text-slate-100">{scenario.title}</h3>
          <p className="text-slate-300 leading-relaxed text-[11px]">{scenario.description}</p>

          <div>
            <span className="text-[11px] text-slate-400 block mb-1 font-bold">Evidence Log Stream:</span>
            <div className="p-3.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-cyan-400 overflow-x-auto space-y-1">
              {scenario.logs.map((log, i) => (
                <div key={i} className="whitespace-pre">{log}</div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Multiple Choice Questions */}
        <div className="lg:col-span-2 glass-panel p-6 space-y-6">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100 font-mono">Defensive Analysis Questions</h3>
            {submitted[scenario.id] && (
              <span className="text-xs font-mono text-emerald-400 font-bold flex items-center gap-1">
                <Award className="w-4 h-4" /> Score: {calculateScore(scenario).correct} / {calculateScore(scenario).total}
              </span>
            )}
          </div>

          <div className="space-y-6">
            {scenario.questions.map((q, index) => {
              const selectedIdx = userAnswers[`${scenario.id}_${q.id}`];
              const isSubmitted = submitted[scenario.id];
              const isCorrect = selectedIdx === q.correctIndex;
              const hintVisible = showHints[`${scenario.id}_${q.id}`];

              return (
                <div key={q.id} className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3 font-mono text-xs">
                  <div className="flex items-start justify-between">
                    <h4 className="font-semibold text-slate-200">
                      Q{index + 1}: {q.questionText}
                    </h4>

                    <button
                      onClick={() => handleToggleHint(q.id)}
                      className="text-[11px] text-amber-400 hover:underline flex items-center space-x-1 shrink-0 ml-2"
                    >
                      <Lightbulb className="w-3.5 h-3.5" />
                      <span>{hintVisible ? 'Hide Hint' : 'Reveal Hint'}</span>
                    </button>
                  </div>

                  {hintVisible && (
                    <div className="p-2.5 rounded bg-amber-950/20 border border-amber-800/40 text-amber-300 text-[11px]">
                      Defensive Hint: {q.defensiveHint}
                    </div>
                  )}

                  {/* Options */}
                  <div className="space-y-2 pt-1">
                    {q.options.map((option, optIdx) => {
                      const isOptionSelected = selectedIdx === optIdx;
                      let optionStyle = 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700';

                      if (isSubmitted) {
                        if (optIdx === q.correctIndex) {
                          optionStyle = 'bg-emerald-950/60 border-emerald-500/80 text-emerald-300 font-bold';
                        } else if (isOptionSelected) {
                          optionStyle = 'bg-rose-950/60 border-rose-500/80 text-rose-300 font-bold';
                        }
                      } else if (isOptionSelected) {
                        optionStyle = 'bg-cyan-950/60 border-cyan-500/80 text-cyan-300 font-bold';
                      }

                      return (
                        <div
                          key={optIdx}
                          onClick={() => handleSelectOption(q.id, optIdx)}
                          className={`p-3 rounded-lg border cursor-pointer transition flex items-center justify-between text-xs ${optionStyle}`}
                        >
                          <span>{option}</span>
                          {isSubmitted && optIdx === q.correctIndex && (
                            <CheckCircle className="w-4 h-4 text-emerald-400" />
                          )}
                          {isSubmitted && isOptionSelected && optIdx !== q.correctIndex && (
                            <XCircle className="w-4 h-4 text-rose-400" />
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Explanation feedback after submit */}
                  {isSubmitted && (
                    <div className={`p-3 rounded-lg border text-[11px] leading-relaxed ${
                      isCorrect ? 'bg-emerald-950/30 border-emerald-800/40 text-emerald-300' : 'bg-rose-950/30 border-rose-800/40 text-rose-300'
                    }`}>
                      <span className="font-bold block mb-0.5">{isCorrect ? 'Correct!' : 'Incorrect.'}</span>
                      {q.explanation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="flex justify-end pt-2">
            {!submitted[scenario.id] && (
              <button
                onClick={handleSubmitScenario}
                disabled={Object.keys(userAnswers).length === 0}
                className="px-5 py-2 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg hover:bg-cyan-500/30 transition text-xs font-mono font-semibold disabled:opacity-50 shadow-glow-cyan"
              >
                Submit Answers & Evaluate
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
