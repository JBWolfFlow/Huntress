/**
 * ChatMessage — CLI-Style Message Renderers
 *
 * Terminal-style output for each message type.
 * Uses the active terminal theme for colors.
 */

import React from 'react';
import type {
  ConversationMessage,
  StrategyOption,
} from '../core/conversation/types';
import { TERMINAL_THEMES, type TerminalTheme } from '../contexts/SettingsContext';

interface ChatMessageProps {
  message: ConversationMessage;
  onStrategySelect?: (strategy: StrategyOption) => void;
  onApprovalRespond?: (approvalId: string, approved: boolean) => void;
  terminalTheme?: TerminalTheme;
  showTimestamps?: boolean;
}

export const ChatMessageComponent: React.FC<ChatMessageProps> = ({
  message,
  onStrategySelect,
  onApprovalRespond,
  terminalTheme = 'hacker',
  showTimestamps = true,
}) => {
  const t = TERMINAL_THEMES[terminalTheme];

  const time = new Date(message.timestamp).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });

  const ts = showTimestamps ? (
    <><span className={t.dimText}>[{time}]</span>{' '}</>
  ) : null;

  switch (message.type) {
    case 'user':
      return (
        <div className="py-0.5">
          {ts}
          <span className="text-cyan-400">you</span>{' '}
          <span className={t.dimText}>{'>'}</span>{' '}
          <span className="text-white">{message.content}</span>
        </div>
      );

    case 'orchestrator':
      return (
        <div className="py-0.5">
          {ts}
          <span className={t.prompt}>huntress</span>{' '}
          <span className={t.dimText}>{'>'}</span>{' '}
          <span className={`${t.aiText} whitespace-pre-wrap`}>{message.content}</span>
        </div>
      );

    case 'agent':
      return (
        <div className="py-0.5">
          {ts}
          <span className={
            message.status === 'running' ? 'text-yellow-400' :
            message.status === 'completed' ? 'text-green-400' : 'text-red-400'
          }>
            {message.agentName}
          </span>{' '}
          <span className={t.dimText}>{'>'}</span>{' '}
          <span className={t.aiText}>{message.content}</span>
        </div>
      );

    case 'system': {
      const icon = message.level === 'error' ? '!' :
                   message.level === 'warning' ? '!' :
                   message.level === 'success' ? '+' : '*';
      const color = message.level === 'error' ? 'text-red-400' :
                    message.level === 'warning' ? 'text-yellow-400' :
                    message.level === 'success' ? 'text-green-400' :
                    t.systemText;
      return (
        <div className="py-0.5">
          {ts}
          <span className={color}>[{icon}]</span>{' '}
          <span className={color}>{message.content}</span>
        </div>
      );
    }

    case 'code_block':
      return (
        <div className="py-1.5">
          {message.title && (
            <div className={`${t.dimText} text-xs mb-0.5`}>
              --- {message.title} ({message.language}) ---
            </div>
          )}
          <div className="bg-gray-950 border border-gray-800 rounded px-3 py-2 overflow-x-auto">
            <pre className="text-green-400 text-xs leading-relaxed">
              <code>{message.content}</code>
            </pre>
          </div>
        </div>
      );

    case 'finding_card': {
      const sevColor =
        message.severity === 'critical' ? 'text-red-500' :
        message.severity === 'high' ? 'text-orange-400' :
        message.severity === 'medium' ? 'text-yellow-400' :
        'text-blue-400';
      const sevBg =
        message.severity === 'critical' ? 'bg-red-500' :
        message.severity === 'high' ? 'bg-orange-500' :
        message.severity === 'medium' ? 'bg-yellow-500' :
        'bg-blue-500';

      return (
        <div className="py-1.5">
          <div className="border border-gray-800 rounded overflow-hidden">
            <div className="px-3 py-1.5 bg-gray-900/50 border-b border-gray-800 flex items-center justify-between">
              <div>
                {ts}
                <span className="text-red-400">[FINDING]</span>{' '}
                <span className="text-white font-bold">{message.title}</span>
              </div>
              <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded text-black ${sevBg}`}>
                {message.severity}
              </span>
            </div>
            <div className="px-3 py-2 space-y-1">
              <div className={t.aiText + ' text-xs'}>{message.description}</div>
              <div className="text-xs">
                <span className={t.dimText}>target:</span>{' '}
                <span className="text-cyan-400">{message.target}</span>
                <span className={`${t.dimText} mx-2`}>|</span>
                <span className={t.dimText}>agent:</span>{' '}
                <span className="text-purple-400">{message.agent}</span>
                {message.isDuplicate && (
                  <>
                    <span className={`${t.dimText} mx-2`}>|</span>
                    <span className="text-yellow-500">[POSSIBLE DUPLICATE]</span>
                  </>
                )}
                {/* Phase 3: Validation status */}
                {message.validationStatus && (
                  <>
                    <span className={`${t.dimText} mx-2`}>|</span>
                    <span className={
                      message.validationStatus === 'confirmed' ? 'text-green-400' :
                      message.validationStatus === 'unverified' ? 'text-yellow-400' :
                      message.validationStatus === 'pending' ? 'text-gray-400' :
                      'text-gray-500'
                    }>
                      [{message.validationStatus === 'confirmed' ? 'VERIFIED' :
                        message.validationStatus === 'unverified' ? 'UNVERIFIED' :
                        message.validationStatus === 'pending' ? 'VALIDATING...' :
                        'CHECK FAILED'}]
                    </span>
                    {message.validationEvidence && message.validationEvidence.length > 0 && (
                      <span className="text-green-400 ml-1">({message.validationEvidence.length} evidence)</span>
                    )}
                  </>
                )}
                {/* Phase 3: Duplicate check status */}
                {message.duplicateCheck && message.duplicateCheck.status !== 'not_checked' && (
                  <>
                    <span className={`${t.dimText} mx-2`}>|</span>
                    <span className={
                      message.duplicateCheck.status === 'likely_duplicate' ? 'text-red-400' :
                      message.duplicateCheck.status === 'possible_duplicate' ? 'text-yellow-400' :
                      'text-green-400'
                    }>
                      [{message.duplicateCheck.status === 'likely_duplicate' ? 'LIKELY DUP' :
                        message.duplicateCheck.status === 'possible_duplicate' ? 'REVIEW DUP' :
                        'NO DUPS'}
                      {message.duplicateCheck.score ? ` ${message.duplicateCheck.score.overall}%` : ''}]
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      );
    }

    case 'strategy_card':
      return (
        <div className="py-1.5">
          <div className={`${t.accent} mb-1`}>
            [*] Recommended attack strategies:
          </div>
          <div className="space-y-0.5 ml-4">
            {message.strategies.map((strategy, i) => (
              <button
                key={strategy.id}
                onClick={() => onStrategySelect?.(strategy)}
                className="block w-full text-left py-1 group hover:bg-gray-900/50 rounded px-2 -ml-2 transition-colors"
              >
                <div>
                  <span className={t.dimText}>[{i + 1}]</span>{' '}
                  <span className="text-white group-hover:text-green-400 transition-colors">
                    {strategy.title}
                  </span>{' '}
                  <span className={`text-xs ${
                    strategy.riskLevel === 'high' ? 'text-red-400' :
                    strategy.riskLevel === 'medium' ? 'text-yellow-400' :
                    'text-green-400'
                  }`}>
                    [{strategy.riskLevel} risk]
                  </span>{' '}
                  <span className="text-green-500 text-xs">{strategy.expectedValue}</span>
                </div>
                <div className={`${t.dimText} text-xs ml-4`}>
                  {strategy.description}
                </div>
                <div className={`${t.dimText} text-xs ml-4`}>
                  agents: {strategy.agents.join(', ')}
                </div>
              </button>
            ))}
          </div>
        </div>
      );

    case 'approval': {
      const statusIcon =
        message.status === 'pending' ? '?' :
        message.status === 'approved' ? '+' : 'x';
      const statusColor =
        message.status === 'pending' ? 'text-yellow-400' :
        message.status === 'approved' ? 'text-green-400' : 'text-red-400';

      return (
        <div className="py-1.5">
          <div className="border border-yellow-900/50 rounded overflow-hidden">
            <div className="px-3 py-1.5 bg-yellow-900/10 border-b border-yellow-900/30">
              <span className={statusColor}>[{statusIcon}]</span>{' '}
              <span className="text-yellow-300 font-bold">APPROVAL REQUIRED</span>
            </div>
            <div className="px-3 py-2 space-y-1">
              <div className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs text-green-400 overflow-x-auto">
                $ {message.command}
              </div>
              <div className="text-xs">
                <span className={t.dimText}>agent:</span>{' '}
                <span className="text-purple-400">{message.agent}</span>
                <span className={`${t.dimText} mx-2`}>|</span>
                <span className={t.dimText}>target:</span>{' '}
                <span className="text-cyan-400">{message.target}</span>
              </div>
              <div className={`${t.dimText} text-xs`}>{message.reasoning}</div>
              {message.status === 'pending' && onApprovalRespond && (
                <div className="flex space-x-2 mt-1">
                  <button
                    onClick={() => onApprovalRespond(message.approvalId, true)}
                    className="px-3 py-1 bg-green-900/50 border border-green-700 text-green-400 rounded text-xs font-bold hover:bg-green-800/50 transition-colors"
                  >
                    [APPROVE]
                  </button>
                  <button
                    onClick={() => onApprovalRespond(message.approvalId, false)}
                    className="px-3 py-1 bg-red-900/50 border border-red-700 text-red-400 rounded text-xs font-bold hover:bg-red-800/50 transition-colors"
                  >
                    [DENY]
                  </button>
                </div>
              )}
              {message.status !== 'pending' && (
                <div className={`text-xs font-bold ${
                  message.status === 'approved' ? 'text-green-400' : 'text-red-400'
                }`}>
                  [{message.status === 'approved' ? 'APPROVED' : 'DENIED'}]
                </div>
              )}
            </div>
          </div>
        </div>
      );
    }

    case 'report_preview':
      return (
        <div className="py-1.5">
          <div className="border border-purple-900/50 rounded overflow-hidden">
            <div className="px-3 py-1.5 bg-purple-900/10 border-b border-purple-900/30 flex items-center justify-between">
              <span className="text-purple-400 font-bold">[REPORT]</span>
              <span className="text-xs text-purple-300">CVSS {message.cvssScore}</span>
            </div>
            <div className="px-3 py-2">
              <div className="text-white font-bold text-sm mb-1">{message.title}</div>
              <pre className={`${t.aiText} text-xs whitespace-pre-wrap leading-relaxed`}>
                {message.markdown.substring(0, 500)}{message.markdown.length > 500 ? '\n...' : ''}
              </pre>
            </div>
          </div>
        </div>
      );

    case 'briefing':
      return (
        <div className="py-1.5">
          <div className="border border-gray-800 rounded overflow-hidden">
            {/* Header */}
            <div className="px-3 py-2 bg-red-900/15 border-b border-gray-800">
              <div className={`${t.accent} font-bold`}>[BRIEFING] {message.programName}</div>
              <div className={`${t.aiText} text-xs mt-0.5`}>{message.targetSummary}</div>
            </div>

            <div className="px-3 py-2 space-y-2">
              {/* Stats */}
              <div className="flex space-x-6 text-xs">
                <div>
                  <span className={t.dimText}>bounty:</span>{' '}
                  <span className="text-green-400 font-bold">
                    ${message.bountyRange.min.toLocaleString()} - ${message.bountyRange.max.toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className={t.dimText}>in-scope:</span>{' '}
                  <span className="text-white font-bold">
                    {message.assets.filter(a => a.inScope).length}
                  </span>
                </div>
                <div>
                  <span className={t.dimText}>out-of-scope:</span>{' '}
                  <span className={t.dimText}>
                    {message.assets.filter(a => !a.inScope).length}
                  </span>
                </div>
              </div>

              {/* Targets */}
              <div>
                <div className={`${t.dimText} text-xs mb-1`}>--- In-Scope Targets ---</div>
                <div className="flex flex-wrap gap-1">
                  {message.assets.filter(a => a.inScope).slice(0, 15).map((asset, i) => (
                    <span key={i} className="text-xs text-green-400 bg-green-900/15 px-1.5 py-0.5 rounded border border-green-900/30">
                      {asset.target}
                    </span>
                  ))}
                  {message.assets.filter(a => a.inScope).length > 15 && (
                    <span className={`text-xs ${t.dimText}`}>
                      +{message.assets.filter(a => a.inScope).length - 15} more
                    </span>
                  )}
                </div>
              </div>

              {/* Strategies */}
              {message.strategies.length > 0 && (
                <div>
                  <div className={`${t.dimText} text-xs mb-1`}>--- Recommended Strategies ---</div>
                  <div className="space-y-0.5">
                    {message.strategies.map((strategy, i) => (
                      <button
                        key={strategy.id}
                        onClick={() => onStrategySelect?.(strategy)}
                        className="block w-full text-left py-1 px-2 rounded hover:bg-gray-900/80 transition-colors group"
                      >
                        <span className={t.dimText}>[{i + 1}]</span>{' '}
                        <span className="text-white group-hover:text-green-400 transition-colors">
                          {strategy.title}
                        </span>{' '}
                        <span className="text-green-500 text-xs">{strategy.expectedValue}</span>
                        <div className={`${t.dimText} text-xs ml-4`}>{strategy.description}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Rules */}
              {message.rules.length > 0 && (
                <div>
                  <div className={`${t.dimText} text-xs mb-1`}>--- Program Rules ---</div>
                  {message.rules.slice(0, 5).map((rule, i) => (
                    <div key={i} className="text-xs text-yellow-400/70 ml-2">
                      <span className="text-yellow-600">*</span>{' '}
                      {rule.length > 120 ? rule.substring(0, 120) + '...' : rule}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      );

    default:
      return null;
  }
};

export default ChatMessageComponent;
