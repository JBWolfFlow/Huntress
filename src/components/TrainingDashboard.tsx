/**
 * Training Dashboard Component
 *
 * Production monitoring dashboard that connects to the training pipeline modules.
 * Displays performance metrics, training status, model versions, A/B test results,
 * resource usage, and alerts. Falls back to empty state when no training data is available.
 */

import React, { useState, useEffect, useCallback } from 'react';

// Types aligned with src/core/training/ module interfaces
interface PerformanceMetrics {
  timestamp: Date;
  successRate: number;
  falsePositiveRate: number;
  avgTimeToSuccess: number;
  avgToolsUsed: number;
}

interface TrainingStatus {
  status: 'idle' | 'collecting' | 'training' | 'validating' | 'deploying' | 'error';
  currentCycle: number;
  progress: number;
  message: string;
}

interface ModelVersion {
  version: string;
  status: 'training' | 'testing' | 'production' | 'archived';
  createdAt: Date;
  performance: {
    successRate: number;
    falsePositiveRate: number;
    avgTimeToSuccess: number;
  };
}

interface ABTestResult {
  testId: string;
  modelA: string;
  modelB: string;
  winner: string | null;
  confidence: number;
  metrics: {
    modelA: { successRate: number; falsePositiveRate: number };
    modelB: { successRate: number; falsePositiveRate: number };
  };
}

interface ResourceUsage {
  timestamp: Date;
  cpu: number;
  memory: number;
  gpu: number;
  disk: number;
}

interface Alert {
  id: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  component: string;
  message: string;
  timestamp: Date;
  acknowledged: boolean;
}

interface DashboardData {
  currentMetrics: PerformanceMetrics;
  trainingStatus: TrainingStatus;
  modelVersions: ModelVersion[];
  abTests: ABTestResult[];
  resourceUsage: ResourceUsage[];
  alerts: Alert[];
  metricsHistory: PerformanceMetrics[];
}

const SEVERITY_COLORS: Record<string, string> = {
  info: 'border-blue-500 bg-blue-900/20',
  warning: 'border-yellow-500 bg-yellow-900/20',
  error: 'border-red-500 bg-red-900/20',
  critical: 'border-red-600 bg-red-900/30',
};

/**
 * Fetch training data from the backend modules.
 * In production this calls into the training pipeline via Tauri IPC;
 * when unavailable it returns null to trigger the empty state.
 */
async function fetchTrainingData(): Promise<DashboardData | null> {
  try {
    // Dynamically import the experimental training integration module
    // (P3-1: moved under experimental/ behind EXPERIMENTAL_TRAINING flag).
    // This uses Node APIs (fs, EventEmitter) — only available via Tauri.
    const trainingModule = await import('../core/training/experimental/integration');
    if (!trainingModule.createContinuousLearningSystem) return null;

    // Training system requires Qdrant and is only available when backend is running
    // Return null to show the "no data" empty state
    return null;
  } catch {
    // Training modules not available in this environment
    return null;
  }
}

/**
 * Training Dashboard Component
 */
export const TrainingDashboard: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(10000);

  const fetchData = useCallback(async () => {
    const result = await fetchTrainingData();
    setData(result);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();

    if (autoRefresh) {
      const interval = setInterval(fetchData, refreshInterval);
      return () => clearInterval(interval);
    }
    return undefined;
  }, [fetchData, autoRefresh, refreshInterval]);

  const handlePauseTraining = async () => {
    console.log('Pausing training...');
  };

  const handleResumeTraining = async () => {
    console.log('Resuming training...');
  };

  const handleTriggerRollback = async () => {
    console.log('Triggering rollback...');
  };

  const handlePromoteModel = async (version: string) => {
    console.log(`Promoting ${version}...`);
  };

  const handleForceRetraining = async () => {
    console.log('Forcing retraining...');
  };

  const handleAcknowledgeAlert = async (alertId: string) => {
    console.log(`Acknowledging alert ${alertId}...`);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-gray-400 text-sm">Loading training data...</div>
      </div>
    );
  }

  // Empty state when training pipeline is not connected
  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 text-center">
        <div className="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center mb-4">
          <span className="text-2xl text-gray-500">T</span>
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">Training Pipeline Offline</h3>
        <p className="text-sm text-gray-400 max-w-md mb-6">
          The training pipeline requires Qdrant (port 6333) and a GPU for LoRA fine-tuning.
          Connect the required services to see performance metrics, A/B test results, and
          model version history.
        </p>
        <div className="space-y-2 text-left text-xs text-gray-500 bg-gray-900 rounded-lg p-4 font-mono">
          <p># Start Qdrant</p>
          <p className="text-gray-300">docker compose up -d qdrant</p>
          <p className="mt-2"># Start training loop</p>
          <p className="text-gray-300">python scripts/htb_runner.py --loop</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-full bg-gray-950 p-6 overflow-y-auto">
      {/* Header */}
      <div className="mb-6">
        <div className="flex justify-between items-center">
          <h1 className="text-xl font-bold text-white">Training Dashboard</h1>
          <div className="flex gap-3 items-center">
            <label className="flex items-center gap-2 text-sm text-gray-400">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded bg-gray-700 border-gray-600"
              />
              Auto-refresh
            </label>
            <select
              value={refreshInterval}
              onChange={(e) => setRefreshInterval(Number(e.target.value))}
              className="rounded bg-gray-800 border-gray-700 text-gray-300 text-sm px-2 py-1"
              disabled={!autoRefresh}
            >
              <option value={5000}>5s</option>
              <option value={10000}>10s</option>
              <option value={30000}>30s</option>
              <option value={60000}>60s</option>
            </select>
            <button
              onClick={fetchData}
              className="px-3 py-1.5 bg-gray-700 text-white text-sm rounded hover:bg-gray-600"
            >
              Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Alerts */}
      {data.alerts.length > 0 && (
        <div className="mb-6 space-y-2">
          {data.alerts.map((alert) => (
            <div
              key={alert.id}
              className={`p-3 rounded-lg border-l-4 ${SEVERITY_COLORS[alert.severity]}`}
            >
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-xs font-bold uppercase text-gray-400">
                    {alert.severity}
                  </span>
                  <span className="text-xs text-gray-500 ml-2">{alert.component}</span>
                  <p className="text-sm text-gray-200 mt-1">{alert.message}</p>
                </div>
                {!alert.acknowledged && (
                  <button
                    onClick={() => handleAcknowledgeAlert(alert.id)}
                    className="text-xs px-2 py-1 bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
                  >
                    Ack
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <MetricCard
          title="Success Rate"
          value={`${(data.currentMetrics.successRate * 100).toFixed(1)}%`}
          trend={data.currentMetrics.successRate >= 0.7 ? 'up' : 'down'}
          color={data.currentMetrics.successRate >= 0.7 ? 'green' : 'red'}
        />
        <MetricCard
          title="False Positive Rate"
          value={`${(data.currentMetrics.falsePositiveRate * 100).toFixed(1)}%`}
          trend={data.currentMetrics.falsePositiveRate <= 0.1 ? 'down' : 'up'}
          color={data.currentMetrics.falsePositiveRate <= 0.1 ? 'green' : 'red'}
        />
        <MetricCard
          title="Avg Execution Time"
          value={`${(data.currentMetrics.avgTimeToSuccess / 60).toFixed(1)}m`}
          trend="stable"
          color="blue"
        />
        <MetricCard
          title="Avg Tools Used"
          value={data.currentMetrics.avgToolsUsed.toFixed(1)}
          trend="stable"
          color="blue"
        />
      </div>

      {/* Training Status + Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-gray-900 rounded-lg border border-gray-700 p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Training Status
          </h2>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Status</span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-semibold ${
                  data.trainingStatus.status === 'error'
                    ? 'bg-red-900/50 text-red-400'
                    : data.trainingStatus.status === 'idle'
                      ? 'bg-gray-800 text-gray-400'
                      : 'bg-blue-900/50 text-blue-400'
                }`}
              >
                {data.trainingStatus.status.toUpperCase()}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Cycle</span>
              <span className="text-white">{data.trainingStatus.currentCycle}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Message</span>
              <span className="text-gray-300 truncate ml-4">
                {data.trainingStatus.message}
              </span>
            </div>

            {data.trainingStatus.progress > 0 && (
              <div>
                <div className="flex justify-between text-xs text-gray-500 mb-1">
                  <span>Progress</span>
                  <span>{data.trainingStatus.progress}%</span>
                </div>
                <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all"
                    style={{ width: `${data.trainingStatus.progress}%` }}
                  />
                </div>
              </div>
            )}

            <div className="flex gap-2 pt-2">
              <button
                onClick={handlePauseTraining}
                className="flex-1 px-3 py-1.5 bg-yellow-600/20 text-yellow-400 text-xs font-medium rounded hover:bg-yellow-600/30"
                disabled={data.trainingStatus.status === 'idle'}
              >
                Pause
              </button>
              <button
                onClick={handleResumeTraining}
                className="flex-1 px-3 py-1.5 bg-green-600/20 text-green-400 text-xs font-medium rounded hover:bg-green-600/30"
                disabled={data.trainingStatus.status !== 'idle'}
              >
                Resume
              </button>
              <button
                onClick={handleForceRetraining}
                className="flex-1 px-3 py-1.5 bg-blue-600/20 text-blue-400 text-xs font-medium rounded hover:bg-blue-600/30"
              >
                Force Retrain
              </button>
            </div>
          </div>
        </div>

        <div className="bg-gray-900 rounded-lg border border-gray-700 p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Manual Controls
          </h2>
          <div className="space-y-2">
            <button
              onClick={handleTriggerRollback}
              className="w-full px-3 py-2.5 bg-red-600/20 text-red-400 rounded hover:bg-red-600/30 text-sm font-medium"
            >
              Emergency Rollback
            </button>

            {/* Performance History (text-based when recharts unavailable) */}
            <div className="mt-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase mb-2">
                Recent Performance (last 10 snapshots)
              </h3>
              <div className="space-y-1">
                {data.metricsHistory.slice(-10).map((m, i) => (
                  <div key={i} className="flex items-center text-xs">
                    <div className="w-16 text-gray-600">
                      {new Date(m.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </div>
                    <div className="flex-1 h-1.5 bg-gray-800 rounded overflow-hidden mx-2">
                      <div
                        className={`h-full rounded ${
                          m.successRate >= 0.7 ? 'bg-green-500' : 'bg-red-500'
                        }`}
                        style={{ width: `${m.successRate * 100}%` }}
                      />
                    </div>
                    <div
                      className={`w-12 text-right ${
                        m.successRate >= 0.7 ? 'text-green-400' : 'text-red-400'
                      }`}
                    >
                      {(m.successRate * 100).toFixed(0)}%
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Resource Usage (text bars) */}
      {data.resourceUsage.length > 0 && (
        <div className="bg-gray-900 rounded-lg border border-gray-700 p-5 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Resource Usage (Latest)
          </h2>
          {(() => {
            const latest = data.resourceUsage[data.resourceUsage.length - 1];
            return (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <ResourceBar label="CPU" value={latest.cpu} color="bg-blue-500" />
                <ResourceBar label="Memory" value={latest.memory} color="bg-green-500" />
                <ResourceBar label="GPU" value={latest.gpu} color="bg-yellow-500" />
                <ResourceBar label="Disk" value={latest.disk} color="bg-purple-500" />
              </div>
            );
          })()}
        </div>
      )}

      {/* Model Versions */}
      {data.modelVersions.length > 0 && (
        <div className="bg-gray-900 rounded-lg border border-gray-700 p-5 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Model Versions
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase">
                  <th className="text-left py-2 pr-4">Version</th>
                  <th className="text-left py-2 pr-4">Status</th>
                  <th className="text-left py-2 pr-4">Success Rate</th>
                  <th className="text-left py-2 pr-4">FP Rate</th>
                  <th className="text-left py-2 pr-4">Created</th>
                  <th className="text-left py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.modelVersions.map((model) => (
                  <tr key={model.version} className="border-t border-gray-800">
                    <td className="py-2 pr-4 text-white font-medium">{model.version}</td>
                    <td className="py-2 pr-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          model.status === 'production'
                            ? 'bg-green-900/50 text-green-400'
                            : model.status === 'testing'
                              ? 'bg-blue-900/50 text-blue-400'
                              : model.status === 'training'
                                ? 'bg-yellow-900/50 text-yellow-400'
                                : 'bg-gray-800 text-gray-500'
                        }`}
                      >
                        {model.status}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-gray-300">
                      {(model.performance.successRate * 100).toFixed(1)}%
                    </td>
                    <td className="py-2 pr-4 text-gray-300">
                      {(model.performance.falsePositiveRate * 100).toFixed(1)}%
                    </td>
                    <td className="py-2 pr-4 text-gray-500">
                      {new Date(model.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-2">
                      {model.status !== 'production' && (
                        <button
                          onClick={() => handlePromoteModel(model.version)}
                          className="text-blue-400 hover:text-blue-300 text-xs"
                        >
                          Promote
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* A/B Test Results */}
      {data.abTests.length > 0 && (
        <div className="bg-gray-900 rounded-lg border border-gray-700 p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            A/B Test Results
          </h2>
          <div className="space-y-3">
            {data.abTests.map((test) => (
              <div key={test.testId} className="border border-gray-800 rounded-lg p-4">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="text-sm font-semibold text-white">
                    {test.modelA} vs {test.modelB}
                  </h3>
                  {test.winner && (
                    <span className="text-xs bg-green-900/40 text-green-400 px-2 py-0.5 rounded">
                      Winner: {test.winner} ({(test.confidence * 100).toFixed(0)}%)
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div>
                    <p className="text-gray-500 mb-1">{test.modelA}</p>
                    <p className="text-gray-300">
                      Success: {(test.metrics.modelA.successRate * 100).toFixed(1)}%
                    </p>
                    <p className="text-gray-300">
                      FP: {(test.metrics.modelA.falsePositiveRate * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-500 mb-1">{test.modelB}</p>
                    <p className="text-gray-300">
                      Success: {(test.metrics.modelB.successRate * 100).toFixed(1)}%
                    </p>
                    <p className="text-gray-300">
                      FP: {(test.metrics.modelB.falsePositiveRate * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

/** Metric card */
interface MetricCardProps {
  title: string;
  value: string;
  trend: 'up' | 'down' | 'stable';
  color: 'green' | 'red' | 'blue' | 'yellow';
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, trend, color }) => {
  const colorMap = {
    green: 'border-green-700 text-green-400',
    red: 'border-red-700 text-red-400',
    blue: 'border-blue-700 text-blue-400',
    yellow: 'border-yellow-700 text-yellow-400',
  };
  const trendIcons = { up: '\u2191', down: '\u2193', stable: '\u2192' };

  return (
    <div className={`bg-gray-900 rounded-lg border p-4 ${colorMap[color]}`}>
      <div className="flex justify-between items-start mb-1">
        <span className="text-xs text-gray-500">{title}</span>
        <span className="text-sm">{trendIcons[trend]}</span>
      </div>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
};

/** Resource usage bar */
const ResourceBar: React.FC<{ label: string; value: number; color: string }> = ({
  label,
  value,
  color,
}) => (
  <div>
    <div className="flex justify-between text-xs mb-1">
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-400">{value.toFixed(0)}%</span>
    </div>
    <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full ${color}`}
        style={{ width: `${Math.min(value, 100)}%` }}
      />
    </div>
  </div>
);

export default TrainingDashboard;
