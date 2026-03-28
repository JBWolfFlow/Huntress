/**
 * Benchmark Dashboard Component
 *
 * Provides a UI for running the XBOW 104-challenge benchmark, displaying
 * results, historical trends, and run comparisons. Connects to the
 * XBOWBenchmarkRunner.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { XBOWBenchmarkRunner } from '../core/benchmark/xbow_runner';
import type { BenchmarkConfig, BenchmarkResult, BenchmarkRun, Challenge, ProgressCallback } from '../core/benchmark/xbow_runner';
import { useSettings } from '../contexts/SettingsContext';
import { getProviderFactory } from '../core/providers/provider_factory';

type RunPhase = 'idle' | 'setup' | 'running' | 'complete' | 'error';

interface ProgressState {
  phase: string;
  current: number;
  total: number;
  message: string;
}

export const BenchmarkDashboard: React.FC = () => {
  const { settings, getApiKey } = useSettings();
  const [runPhase, setRunPhase] = useState<RunPhase>('idle');
  const [progress, setProgress] = useState<ProgressState | null>(null);
  const [latestResult, setLatestResult] = useState<BenchmarkResult | null>(null);
  const [history, setHistory] = useState<BenchmarkRun[]>([]);
  const [, setChallenges] = useState<Challenge[]>([]);
  const [error, setError] = useState<string | null>(null);
  const runnerRef = useRef<XBOWBenchmarkRunner | null>(null);

  const getRunner = useCallback((): XBOWBenchmarkRunner | null => {
    if (runnerRef.current) return runnerRef.current;

    const { providerId, modelId } = settings.orchestratorModel;
    const apiKey = getApiKey(providerId);
    if (!apiKey && providerId !== 'local') return null;

    try {
      const factory = getProviderFactory();
      const provider = factory.create(providerId, { apiKey });

      const config: BenchmarkConfig = {
        benchmarkDir: '/tmp/huntress-xbow-bench',
        provider,
        model: modelId,
        dbPath: 'huntress_knowledge.db',
        maxParallel: 2,
        onProgress: ((phase: string, current: number, total: number, message: string) => {
          setProgress({ phase, current, total, message });
        }) satisfies ProgressCallback,
      };

      const runner = new XBOWBenchmarkRunner(config);
      runnerRef.current = runner;
      return runner;
    } catch {
      return null;
    }
  }, [settings.orchestratorModel, getApiKey]);

  // Load history on mount
  useEffect(() => {
    const runner = getRunner();
    if (!runner) return;

    runner.getHistory().then(h => setHistory(h)).catch(() => {});
    runner.listChallenges().then(c => setChallenges(c)).catch(() => {});
  }, [getRunner]);

  const handleRunBenchmark = async () => {
    const runner = getRunner();
    if (!runner) {
      setError('No AI provider configured. Go to Settings to add an API key.');
      return;
    }

    setRunPhase('setup');
    setError(null);

    try {
      await runner.setup();
      setRunPhase('running');
      const result = await runner.runBenchmark();
      setLatestResult(result);
      setRunPhase('complete');

      // Refresh history
      const h = await runner.getHistory();
      setHistory(h);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setRunPhase('error');
    }
  };

  // ── Idle / No Provider State ──
  if (runPhase === 'idle' && !latestResult && history.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-center font-mono">
        <div className="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center mb-4">
          <span className="text-2xl text-gray-500">B</span>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">XBOW Benchmark</h3>
        <p className="text-sm text-gray-400 max-w-md mb-6">
          Run the 104-challenge Docker CTF benchmark to measure agent performance.
          Requires Docker and an AI provider API key.
        </p>
        <button
          onClick={handleRunBenchmark}
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded font-mono text-sm transition-colors"
        >
          [run benchmark]
        </button>
        {error && (
          <p className="text-red-400 text-xs mt-4 max-w-md">{error}</p>
        )}
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto p-4 font-mono text-sm">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-white font-bold">
          <span className="text-red-500">[</span>BENCHMARK<span className="text-red-500">]</span>
        </h2>
        <button
          onClick={handleRunBenchmark}
          disabled={runPhase === 'running' || runPhase === 'setup'}
          className="px-3 py-1 bg-red-600 hover:bg-red-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded text-xs transition-colors"
        >
          {runPhase === 'running' || runPhase === 'setup' ? '[running...]' : '[run benchmark]'}
        </button>
      </div>

      {/* Progress Bar */}
      {(runPhase === 'running' || runPhase === 'setup') && progress && (
        <div className="mb-4 border border-gray-700 rounded p-3 bg-gray-900">
          <div className="flex justify-between text-xs text-gray-400 mb-1">
            <span>{progress.phase}</span>
            <span>{progress.current}/{progress.total}</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-red-500 h-2 rounded-full transition-all"
              style={{ width: `${progress.total > 0 ? (progress.current / progress.total) * 100 : 0}%` }}
            />
          </div>
          <p className="text-xs text-gray-500 mt-1">{progress.message}</p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mb-4 border border-red-800 rounded p-3 bg-red-900/20 text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Latest Result */}
      {latestResult && (
        <div className="mb-6">
          <h3 className="text-gray-400 text-xs mb-2">--- LATEST RUN ---</h3>
          <div className="grid grid-cols-4 gap-3">
            <StatCard
              label="Score"
              value={`${latestResult.scorePercent.toFixed(1)}%`}
              color={latestResult.scorePercent >= 50 ? 'text-green-400' : 'text-yellow-400'}
            />
            <StatCard label="Solved" value={`${latestResult.solved}/${latestResult.totalChallenges}`} color="text-white" />
            <StatCard label="Cost" value={`$${latestResult.totalCostUsd.toFixed(2)}`} color="text-blue-400" />
            <StatCard label="Duration" value={formatDuration(latestResult.totalDurationMs)} color="text-gray-300" />
          </div>

          {/* Per-challenge breakdown */}
          {latestResult.results.length > 0 && (
            <div className="mt-3 border border-gray-800 rounded p-3">
              <h4 className="text-xs text-gray-500 mb-2">Results</h4>
              <div className="space-y-1">
                {latestResult.results.map(cr => (
                  <div key={cr.challengeId} className="flex justify-between text-xs">
                    <span className="text-gray-300">{cr.challengeId}</span>
                    <span className={cr.solved ? 'text-green-400' : 'text-red-400'}>
                      {cr.solved ? 'SOLVED' : 'FAILED'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div>
          <h3 className="text-gray-400 text-xs mb-2">--- HISTORY ({history.length} runs) ---</h3>
          <div className="space-y-1">
            {history.map((run, i) => (
              <div key={run.id} className="flex justify-between text-xs border-b border-gray-800 py-1">
                <span className="text-gray-400">#{history.length - i}</span>
                <span className="text-white">{run.score.toFixed(1)}%</span>
                <span className="text-gray-500">{run.solved}/{run.totalChallenges}</span>
                <span className="text-blue-400">${run.totalCostUsd.toFixed(2)}</span>
                <span className="text-gray-500">{new Date(run.timestamp).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

function StatCard({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="border border-gray-800 rounded p-2">
      <div className="text-xs text-gray-500">{label}</div>
      <div className={`text-lg font-bold ${color}`}>{value}</div>
    </div>
  );
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes}m ${remaining}s`;
}

export default BenchmarkDashboard;
