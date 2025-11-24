/**
 * Terminal Component
 *
 * Displays PTY output in a terminal-like interface
 */

import React, { useEffect, useRef, useState } from 'react';
import { usePTYStream } from '../hooks/useTauriCommands';

interface TerminalProps {
  ptyId: string | null;
  onData?: (data: string) => void;
}

export const Terminal: React.FC<TerminalProps> = ({ ptyId, onData }) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const output = usePTYStream(ptyId, 100);

  // Auto-scroll to bottom when new output arrives
  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output, autoScroll]);

  // Notify parent of new data
  useEffect(() => {
    if (output && onData) {
      onData(output);
    }
  }, [output, onData]);

  // Handle manual scroll - disable auto-scroll if user scrolls up
  const handleScroll = () => {
    if (terminalRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = terminalRef.current;
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 10;
      setAutoScroll(isAtBottom);
    }
  };

  return (
    <div className="terminal-wrapper h-full flex flex-col bg-black">
      {/* Terminal Header */}
      <div className="terminal-header bg-gray-800 px-3 py-2 flex items-center justify-between border-b border-gray-700">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
          <span className="ml-3 text-sm text-gray-400">
            {ptyId ? `Session: ${ptyId.substring(0, 8)}...` : 'No active session'}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          {ptyId && (
            <span className="text-xs text-green-400 flex items-center">
              <span className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></span>
              Recording
            </span>
          )}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`text-xs px-2 py-1 rounded ${
              autoScroll ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
            }`}
            title={autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll disabled'}
          >
            {autoScroll ? 'AUTO' : 'MANUAL'}
          </button>
        </div>
      </div>

      {/* Terminal Output */}
      <div
        ref={terminalRef}
        onScroll={handleScroll}
        className="terminal-output flex-1 overflow-y-auto p-4 font-mono text-sm text-green-400"
        style={{
          backgroundColor: '#000000',
          lineHeight: '1.5',
        }}
      >
        {ptyId ? (
          output ? (
            <pre className="whitespace-pre-wrap break-words">{output}</pre>
          ) : (
            <div className="text-gray-500 italic">Waiting for output...</div>
          )
        ) : (
          <div className="text-gray-500 italic text-center mt-8">
            No active PTY session. Start a hunt to see output here.
          </div>
        )}
      </div>
    </div>
  );
};

export default Terminal;