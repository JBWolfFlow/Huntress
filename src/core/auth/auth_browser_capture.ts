/**
 * Auth Browser Capture (Phase B)
 *
 * Launches a visible browser for the user to log into, capturing auth
 * headers, cookies, and tokens automatically.
 *
 * Architecture: Playwright CANNOT run inside Tauri's WebView (browser context).
 * Instead, this module invokes a standalone Node.js script via Tauri IPC
 * (execute_training_command), which runs Playwright in a proper Node.js process.
 * The script outputs JSON to stdout, which we parse here.
 */

import { invoke } from '@tauri-apps/api/core';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CapturedAuth {
  /** Bearer/API tokens from Authorization headers */
  bearerToken?: string;
  /** All cookies captured from scope domains */
  cookies: CapturedCookie[];
  /** Custom auth headers (e.g., wallet-authorization, x-csrf-token) */
  customHeaders: Record<string, string>;
  /** Final URL after login flow completed */
  finalUrl: string;
  /** localStorage entries from scope domains */
  localStorage: Record<string, string>;
  /** sessionStorage entries from scope domains */
  sessionStorage: Record<string, string>;
}

export interface CapturedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
}

export type CaptureStatus =
  | { phase: 'launching'; message: string }
  | { phase: 'waiting'; message: string }
  | { phase: 'captured'; message: string }
  | { phase: 'error'; message: string }
  | { phase: 'timeout'; message: string };

// ─── Auth Browser Capture ───────────────────────────────────────────────────

export class AuthBrowserCapture {
  /** Launch a visible browser via external Node.js process, capture auth after login.
   *  @param loginUrl — The login page URL to navigate to
   *  @param scopeDomains — Domains to intercept traffic on
   *  @param onStatus — Real-time status callback
   *  @param timeoutMs — Max time to wait for login (default: 120000)
   */
  async captureAuth(
    loginUrl: string,
    scopeDomains: string[],
    onStatus?: (status: CaptureStatus) => void,
    timeoutMs: number = 120_000,
  ): Promise<CapturedAuth> {
    const emit = (status: CaptureStatus) => onStatus?.(status);

    try {
      emit({ phase: 'launching', message: 'Launching browser (Node.js subprocess)...' });

      // Invoke the standalone Node.js script via Tauri IPC.
      // The script runs Playwright in a proper Node.js process (not the WebView).
      const result = await invoke<{
        exitCode: number;
        stdout: string;
        stderr: string;
        success: boolean;
      }>('execute_training_command', {
        program: 'node',
        args: [
          '../scripts/auth_capture.mjs',
          loginUrl,
          scopeDomains.join(','),
          String(timeoutMs),
        ],
        cwd: null,
      });

      if (!result.success) {
        const errorMsg = result.stderr || `Node process exited with code ${result.exitCode}`;
        emit({ phase: 'error', message: errorMsg });
        throw new Error(errorMsg);
      }

      // Parse JSON from stdout (the script outputs the CapturedAuth object)
      const stdout = result.stdout.trim();
      if (!stdout) {
        emit({ phase: 'error', message: 'No output from capture script' });
        throw new Error('No output from auth capture script');
      }

      // Find the last line that starts with '{' — skip any non-JSON output
      const lines = stdout.split('\n');
      const jsonLine = lines.reverse().find(l => l.trim().startsWith('{'));
      if (!jsonLine) {
        emit({ phase: 'error', message: 'No JSON output from capture script' });
        throw new Error('No JSON output from auth capture script');
      }

      const parsed = JSON.parse(jsonLine);

      if (parsed.error) {
        emit({ phase: 'error', message: parsed.error });
        throw new Error(parsed.error);
      }

      const captured: CapturedAuth = {
        bearerToken: parsed.bearerToken ?? undefined,
        cookies: parsed.cookies ?? [],
        customHeaders: parsed.customHeaders ?? {},
        finalUrl: parsed.finalUrl ?? loginUrl,
        localStorage: parsed.localStorage ?? {},
        sessionStorage: parsed.sessionStorage ?? {},
      };

      const parts: string[] = [];
      if (captured.bearerToken) parts.push('bearer token');
      if (captured.cookies.length > 0) parts.push(`${captured.cookies.length} cookies`);
      if (Object.keys(captured.customHeaders).length > 0) parts.push(`${Object.keys(captured.customHeaders).length} custom headers`);

      emit({
        phase: parts.length > 0 ? 'captured' : 'timeout',
        message: parts.length > 0
          ? `Captured: ${parts.join(', ')}`
          : 'No auth credentials detected',
      });

      return captured;
    } catch (err) {
      if (err instanceof Error && !err.message.includes('capture')) {
        emit({ phase: 'error', message: err.message });
      }
      throw err;
    }
  }

  /** No-op cleanup — the Node.js subprocess manages its own lifecycle */
  async cleanup(): Promise<void> {
    // Nothing to clean up — the subprocess closes the browser on exit
  }
}
