/**
 * ReportEditor
 *
 * Split-pane markdown editor: edit on the left, preview on the right.
 * Pre-filled from PoCGenerator output. Shows CVSS score, duplicate check,
 * and provides a "Submit to HackerOne" button.
 */

import React, { useState, useCallback } from 'react';
import type { H1Report } from '../core/reporting/h1_api';

interface ReportEditorProps {
  report: H1Report;
  programHandle: string;
  onSubmit?: (report: H1Report, programHandle: string) => Promise<void>;
  onClose?: () => void;
}

/** Convert an H1Report to editable markdown */
function reportToMarkdown(report: H1Report): string {
  let md = `# ${report.title}\n\n`;

  md += `**Severity:** ${report.severity.toUpperCase()}\n`;
  md += `**Suggested Bounty:** $${report.suggestedBounty.min.toLocaleString()} - $${report.suggestedBounty.max.toLocaleString()}\n`;
  if (report.cvssScore) md += `**CVSS Score:** ${report.cvssScore}\n`;
  if (report.weaknessId) md += `**CWE:** CWE-${report.weaknessId}\n`;
  md += '\n---\n\n';

  md += `## Description\n\n${report.description}\n\n`;
  md += `## Impact\n\n${report.impact}\n\n`;

  md += `## Steps to Reproduce\n\n`;
  report.steps.forEach((step, i) => {
    md += `${i + 1}. ${step}\n`;
  });
  md += '\n';

  if (report.proof.video || report.proof.screenshots?.length || report.proof.logs?.length) {
    md += `## Proof of Concept\n\n`;
    if (report.proof.video) md += `**Video:** ${report.proof.video}\n\n`;
    if (report.proof.screenshots?.length) {
      md += `**Screenshots:**\n`;
      report.proof.screenshots.forEach((s, i) => {
        md += `- Screenshot ${i + 1}: ${s}\n`;
      });
      md += '\n';
    }
    if (report.proof.logs?.length) {
      md += `**Logs:**\n`;
      report.proof.logs.forEach((l, i) => {
        md += `- Log ${i + 1}: ${l}\n`;
      });
      md += '\n';
    }
  }

  if (report.severityJustification?.length) {
    md += `## Severity Justification\n\n`;
    report.severityJustification.forEach((r) => {
      md += `- ${r}\n`;
    });
    md += '\n';
  }

  return md;
}

/** Simple markdown-to-HTML renderer (headings, bold, lists, hr, code) */
/** Escape HTML entities to prevent XSS in the preview pane */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderMarkdown(md: string): string {
  // Escape HTML first to prevent XSS, then apply markdown formatting
  return escapeHtml(md)
    .replace(/^### (.+)$/gm, '<h3 class="text-base font-semibold text-white mt-4 mb-2">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold text-white mt-5 mb-2">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="text-xl font-bold text-white mt-6 mb-3">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white">$1</strong>')
    .replace(/^---$/gm, '<hr class="border-gray-700 my-4" />')
    .replace(/^\d+\. (.+)$/gm, '<li class="ml-4 list-decimal text-gray-300 text-sm">$1</li>')
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-gray-300 text-sm">$1</li>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-800 px-1 rounded text-red-400 text-sm">$1</code>')
    .replace(/\n/g, '<br />');
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
};

export const ReportEditor: React.FC<ReportEditorProps> = ({
  report,
  programHandle,
  onSubmit,
  onClose,
}) => {
  const [markdown, setMarkdown] = useState(() => reportToMarkdown(report));
  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<{ success: boolean; message: string } | null>(
    null
  );

  const handleSubmit = useCallback(async () => {
    if (!onSubmit) return;
    setSubmitting(true);
    setSubmitResult(null);
    try {
      // Merge user-edited markdown into the report so edits are preserved
      const editedReport = { ...report, description: markdown };
      await onSubmit(editedReport, programHandle);
      setSubmitResult({ success: true, message: 'Report submitted successfully!' });
    } catch (err) {
      setSubmitResult({
        success: false,
        message: err instanceof Error ? err.message : 'Submission failed',
      });
    } finally {
      setSubmitting(false);
    }
  }, [onSubmit, report, programHandle, markdown]);

  return (
    <div className="flex flex-col h-full bg-gray-900">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700 bg-gray-800">
        <div className="flex items-center space-x-3">
          <h2 className="text-sm font-bold text-white">Report Editor</h2>
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase text-white ${
              SEVERITY_COLORS[report.severity] ?? 'bg-gray-500'
            }`}
          >
            {report.severity}
          </span>
          {report.cvssScore && (
            <span className="text-xs text-gray-400">CVSS {report.cvssScore}</span>
          )}
          {report.weaknessId && (
            <span className="text-xs text-gray-400">CWE-{report.weaknessId}</span>
          )}
        </div>

        <div className="flex items-center space-x-2">
          {report.duplicateCheck && (
            <span
              className={`text-xs px-2 py-0.5 rounded ${
                report.duplicateCheck.recommendation === 'submit'
                  ? 'bg-green-900/40 text-green-400'
                  : report.duplicateCheck.recommendation === 'review'
                    ? 'bg-yellow-900/40 text-yellow-400'
                    : 'bg-red-900/40 text-red-400'
              }`}
            >
              Dup Score: {report.duplicateCheck.overall}/100
            </span>
          )}
          {onClose && (
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white text-sm px-2 py-1"
            >
              Close
            </button>
          )}
        </div>
      </div>

      {/* Split panes */}
      <div className="flex-1 flex overflow-hidden">
        {/* Editor pane */}
        <div className="w-1/2 flex flex-col border-r border-gray-700">
          <div className="px-3 py-1.5 bg-gray-800/50 border-b border-gray-700">
            <span className="text-[10px] font-semibold text-gray-500 uppercase">Edit</span>
          </div>
          <textarea
            value={markdown}
            onChange={(e) => setMarkdown(e.target.value)}
            className="flex-1 p-4 bg-transparent text-gray-300 text-sm font-mono resize-none focus:outline-none"
            spellCheck={false}
          />
        </div>

        {/* Preview pane */}
        <div className="w-1/2 flex flex-col">
          <div className="px-3 py-1.5 bg-gray-800/50 border-b border-gray-700">
            <span className="text-[10px] font-semibold text-gray-500 uppercase">Preview</span>
          </div>
          <div
            className="flex-1 p-4 overflow-y-auto text-gray-300 text-sm prose prose-invert max-w-none"
            dangerouslySetInnerHTML={{ __html: renderMarkdown(markdown) }}
          />
        </div>
      </div>

      {/* Submission result */}
      {submitResult && (
        <div
          className={`px-4 py-2 text-sm ${
            submitResult.success
              ? 'bg-green-900/30 text-green-400'
              : 'bg-red-900/30 text-red-400'
          }`}
        >
          {submitResult.message}
        </div>
      )}

      {/* Footer actions */}
      <div className="flex items-center justify-between px-4 py-3 border-t border-gray-700 bg-gray-800">
        <div className="text-xs text-gray-500">
          Target: <span className="text-gray-300">{programHandle}</span>
          {report.suggestedBounty && (
            <>
              {' '}
              &middot; Est. Bounty:{' '}
              <span className="text-green-400">
                ${report.suggestedBounty.min.toLocaleString()} - $
                {report.suggestedBounty.max.toLocaleString()}
              </span>
            </>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => {
              navigator.clipboard.writeText(markdown);
            }}
            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs font-medium rounded transition-colors"
          >
            Copy Markdown
          </button>
          {onSubmit && (
            <button
              onClick={handleSubmit}
              disabled={submitting}
              className="px-4 py-1.5 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-xs font-semibold rounded transition-colors"
            >
              {submitting ? 'Submitting...' : 'Submit to HackerOne'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportEditor;
