/**
 * ChatInterface — CLI-Style Terminal
 *
 * Terminal-style interface with customizable themes, prompts,
 * and structured output. The primary interaction surface.
 */

import React, { useState, useRef, useEffect, useMemo } from 'react';
import { useHuntSession } from '../contexts/HuntSessionContext';
import { useSettings, TERMINAL_THEMES, PROMPT_FORMATS } from '../contexts/SettingsContext';
import { ChatMessageComponent } from './ChatMessage';
import type { StrategyOption } from '../core/conversation/types';

export const ChatInterface: React.FC = () => {
  const {
    messages,
    sendMessage,
    selectStrategy,
    phase,
  } = useHuntSession();

  const { settings } = useSettings();
  const theme = TERMINAL_THEMES[settings.terminal.theme];
  const promptFmt = PROMPT_FORMATS[settings.terminal.promptStyle];

  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSend = async () => {
    const trimmed = input.trim();
    if (!trimmed || sending) return;

    setHistory(prev => [trimmed, ...prev].slice(0, 50));
    setHistoryIndex(-1);
    setInput('');
    setSending(true);
    try {
      await sendMessage(trimmed);
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSend();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0) {
        const newIndex = Math.min(historyIndex + 1, history.length - 1);
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      } else {
        setHistoryIndex(-1);
        setInput('');
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      // Ctrl+L to clear screen (like a real terminal)
      e.preventDefault();
      // Scroll to bottom and visually clear by scrolling past all messages
      messagesEndRef.current?.scrollIntoView({ behavior: 'instant' });
    }
  };

  const handleStrategySelect = async (strategy: StrategyOption) => {
    await selectStrategy(strategy);
  };

  const handleContainerClick = () => {
    inputRef.current?.focus();
  };

  // Virtualization: only render the last 200 messages for performance with 1000+ message sessions
  const RENDER_WINDOW = 200;
  const [showAllMessages, setShowAllMessages] = useState(false);
  const visibleMessages = useMemo(() => {
    if (showAllMessages || messages.length <= RENDER_WINDOW) return messages;
    return messages.slice(-RENDER_WINDOW);
  }, [messages, showAllMessages]);
  const hiddenCount = messages.length - visibleMessages.length;

  const promptText = promptFmt.format(phase);

  return (
    <div
      className={`flex-1 flex flex-col min-h-0 ${theme.bg} font-mono`}
      style={{ fontSize: `${settings.terminal.fontSize}px` }}
      onClick={handleContainerClick}
    >
      {/* Terminal Output */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-0">
        {messages.length === 0 && (
          <div className="py-4">
            <pre className={`${theme.accent} text-xs leading-tight`}>{`
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗██████╗ ███████╗███████╗███████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
  ███████║██║   ██║██╔██╗ ██║   ██║   ██████╔╝█████╗  ███████╗███████╗
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██║███████╗███████║███████║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝`}</pre>
            <div className={`mt-4 ${theme.aiText}`}>
              [*] Huntress AI Bug Bounty Platform v0.1.0
            </div>
            <div className={`mt-1 ${theme.systemText}`}>
              [*] Type a message or import a bounty program to begin
            </div>
            <div className={`mt-1 ${theme.dimText}`}>
              [*] Customize this terminal in Settings {'>'} Terminal
            </div>
            <div className={`${theme.dimText} mt-3`}>
              --- Quick Commands ---
            </div>
            <div className="ml-4 mt-1 space-y-1">
              {[
                'Analyze example.com for OAuth vulnerabilities',
                'What attack strategies work best for API targets?',
                'Help me understand SSRF exploitation',
              ].map((cmd, i) => (
                <button
                  key={i}
                  onClick={(e) => { e.stopPropagation(); setInput(cmd); inputRef.current?.focus(); }}
                  className={`block text-left ${theme.systemText} hover:${theme.userText} transition-colors w-full`}
                >
                  <span className={theme.accent}>{'>'}</span> {cmd}
                </button>
              ))}
            </div>
          </div>
        )}

        {hiddenCount > 0 && (
          <button
            onClick={() => setShowAllMessages(true)}
            className={`${theme.dimText} hover:${theme.systemText} py-1 text-xs transition-colors`}
          >
            [{hiddenCount} earlier messages hidden — click to show all]
          </button>
        )}

        {visibleMessages.map((msg) => (
          <ChatMessageComponent
            key={msg.id}
            message={msg}
            onStrategySelect={handleStrategySelect}
            onApprovalRespond={(approvalId, approved) => {
              const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (approved: boolean) => void> | undefined;
              callbacks?.get(approvalId)?.(approved);
              callbacks?.delete(approvalId);
            }}
            terminalTheme={settings.terminal.theme}
            showTimestamps={settings.terminal.showTimestamps}
          />
        ))}

        {sending && (
          <div className="py-1">
            <span className={`${theme.accent} animate-pulse`}>[*] Processing...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Command Input */}
      <div className="border-t border-gray-800 bg-gray-950 px-4 py-3">
        <div className="flex items-center">
          <span className={`${theme.prompt} font-bold mr-1`}>
            {promptText}
          </span>
          <span className={`${theme.dimText} mr-2`}>
            {settings.terminal.promptStyle === 'minimal' || settings.terminal.promptStyle === 'root' ? '' : '>'}
          </span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={sending ? 'Processing...' : ''}
            disabled={sending}
            className={`flex-1 bg-transparent ${theme.userText} outline-none placeholder-gray-700 font-mono disabled:opacity-50`}
            style={{ caretColor: 'currentColor' }}
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <div className="flex items-center justify-between mt-1">
          <div className={`text-xs ${theme.dimText}`}>
            {phase !== 'idle' && (
              <span>phase: <span className={theme.accent}>{phase}</span> | </span>
            )}
            <span>msgs: {messages.length}</span>
            {history.length > 0 && <span> | hist: {history.length}</span>}
          </div>
          <div className={`text-xs ${theme.dimText}`}>
            ↑↓ history | enter send
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChatInterface;
