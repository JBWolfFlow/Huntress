/**
 * OAuth Hunter Test Component
 * 
 * UI component for testing OAuth Hunter integration in the Huntress application
 */

import React, { useState } from 'react';
import { runAllTests } from '../tests/oauth_integration_test';

interface TestResult {
  success: boolean;
  results: any;
  duration: number;
  error?: string;
}

export const OAuthTester: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const handleRunTests = async () => {
    setIsRunning(true);
    setTestResult(null);
    setLogs(['Starting OAuth Hunter integration tests...']);

    // Capture console logs
    const originalLog = console.log;
    const originalError = console.error;
    const capturedLogs: string[] = [];

    console.log = (...args: any[]) => {
      const message = args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ');
      capturedLogs.push(message);
      setLogs(prev => [...prev, message]);
      originalLog(...args);
    };

    console.error = (...args: any[]) => {
      const message = '[ERROR] ' + args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ');
      capturedLogs.push(message);
      setLogs(prev => [...prev, message]);
      originalError(...args);
    };

    try {
      const result = await runAllTests();
      setTestResult(result);
      setLogs(prev => [...prev, '\n✓ All tests completed successfully!']);
    } catch (error) {
      setTestResult({
        success: false,
        results: {},
        duration: 0,
        error: error instanceof Error ? error.message : String(error),
      });
      setLogs(prev => [...prev, `\n✗ Tests failed: ${error}`]);
    } finally {
      // Restore console
      console.log = originalLog;
      console.error = originalError;
      setIsRunning(false);
    }
  };

  const handleClearLogs = () => {
    setLogs([]);
    setTestResult(null);
  };

  return (
    <div className="oauth-tester p-6 max-w-6xl mx-auto">
      <div className="bg-gray-900 rounded-lg shadow-xl p-6 mb-6">
        <h2 className="text-2xl font-bold text-white mb-4">
          OAuth Hunter Integration Tester
        </h2>
        
        <div className="flex gap-4 mb-6">
          <button
            onClick={handleRunTests}
            disabled={isRunning}
            className={`px-6 py-3 rounded-lg font-semibold transition-colors ${
              isRunning
                ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 text-white'
            }`}
          >
            {isRunning ? 'Running Tests...' : 'Run All Tests'}
          </button>
          
          <button
            onClick={handleClearLogs}
            disabled={isRunning}
            className="px-6 py-3 rounded-lg font-semibold bg-gray-700 hover:bg-gray-600 text-white transition-colors"
          >
            Clear Logs
          </button>
        </div>

        {testResult && (
          <div className={`p-4 rounded-lg mb-6 ${
            testResult.success ? 'bg-green-900/30 border border-green-500' : 'bg-red-900/30 border border-red-500'
          }`}>
            <h3 className={`text-lg font-bold mb-2 ${
              testResult.success ? 'text-green-400' : 'text-red-400'
            }`}>
              {testResult.success ? '✓ Tests Passed' : '✗ Tests Failed'}
            </h3>
            <div className="text-gray-300 space-y-1">
              <p>Duration: {testResult.duration}ms</p>
              {testResult.error && (
                <p className="text-red-400">Error: {testResult.error}</p>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="bg-gray-900 rounded-lg shadow-xl p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-xl font-bold text-white">Test Output</h3>
          <span className="text-sm text-gray-400">
            {logs.length} log entries
          </span>
        </div>
        
        <div className="bg-black rounded-lg p-4 h-96 overflow-y-auto font-mono text-sm">
          {logs.length === 0 ? (
            <p className="text-gray-500">No logs yet. Click "Run All Tests" to start.</p>
          ) : (
            logs.map((log, index) => (
              <div
                key={index}
                className={`mb-1 ${
                  log.includes('[ERROR]') ? 'text-red-400' :
                  log.includes('✓') ? 'text-green-400' :
                  log.includes('✗') ? 'text-red-400' :
                  log.includes('[APPROVAL') ? 'text-yellow-400' :
                  log.includes('TEST') ? 'text-blue-400' :
                  'text-gray-300'
                }`}
              >
                {log}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="mt-6 bg-gray-900 rounded-lg shadow-xl p-6">
        <h3 className="text-xl font-bold text-white mb-4">Test Coverage</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-800 rounded-lg p-4">
            <h4 className="font-semibold text-blue-400 mb-2">Test 1: Basic OAuth Hunt</h4>
            <p className="text-sm text-gray-400">
              Tests full OAuth hunt workflow with human approval
            </p>
          </div>
          
          <div className="bg-gray-800 rounded-lg p-4">
            <h4 className="font-semibold text-blue-400 mb-2">Test 2: Specific Vulnerability Types</h4>
            <p className="text-sm text-gray-400">
              Tests redirect, state, PKCE, and scope validators individually
            </p>
          </div>
          
          <div className="bg-gray-800 rounded-lg p-4">
            <h4 className="font-semibold text-blue-400 mb-2">Test 3: Human-in-the-Loop</h4>
            <p className="text-sm text-gray-400">
              Verifies approval workflow and human task management
            </p>
          </div>
          
          <div className="bg-gray-800 rounded-lg p-4">
            <h4 className="font-semibold text-blue-400 mb-2">Test 4: Report Generation</h4>
            <p className="text-sm text-gray-400">
              Tests vulnerability report generation
            </p>
          </div>
          
          <div className="bg-gray-800 rounded-lg p-4">
            <h4 className="font-semibold text-blue-400 mb-2">Test 5: Agent Capabilities</h4>
            <p className="text-sm text-gray-400">
              Verifies agent registration and capability reporting
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OAuthTester;