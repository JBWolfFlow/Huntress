/**
 * Terminal Component
 * 
 * Renders an xterm.js terminal for displaying tool output
 */

import React, { useEffect, useRef } from 'react';

interface TerminalProps {
  ptyId: string;
  onData?: (data: string) => void;
}

export const Terminal: React.FC<TerminalProps> = ({ ptyId, onData }) => {
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // TODO: Initialize xterm.js terminal
    // TODO: Connect to PTY output stream
    // TODO: Handle input and send to PTY
  }, [ptyId]);

  return (
    <div 
      ref={terminalRef} 
      className="terminal-container w-full h-full bg-black"
    />
  );
};

export default Terminal;