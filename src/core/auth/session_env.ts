/**
 * Session environment builder (Phase 1 / Q1)
 *
 * Exports an active AuthenticatedSession as sandbox-ready env vars and a
 * pre-stamped ~/.curlrc, so shell-tool agents (curl, ffuf, nuclei, sqlmap)
 * inherit auth without the LLM having to paste tokens into commands.
 *
 * Naming convention:
 *   HUNTRESS_AUTH_ + UPPERCASE(headerName) with `-` → `_`
 *   Cookie jar: HUNTRESS_AUTH_COOKIE (joined with "; ")
 *   CSRF:       HUNTRESS_AUTH_CSRF_TOKEN
 *
 * Rust sandbox.validate_env blocks PATH/HOME/USER/SHELL/HOSTNAME and the
 * LD_ / DOCKER_ / PODMAN_ / SUDO_ / XDG_ prefixes. HUNTRESS_AUTH_* is clear.
 */
import type { AuthenticatedSession } from './session_manager';

export interface SessionEnv {
  /** Env vars to pass into the sandbox via SandboxConfig.env_vars */
  envVars: Record<string, string>;
  /** Contents of ~/.curlrc inside the container (empty when no auth) */
  curlrcContent: string;
  /** One-line human summary for logging */
  promptSummary: string;
}

/** Canonicalize a header name to a HUNTRESS_AUTH_* env var name. */
export function headerNameToEnvVar(headerName: string): string {
  const upper = headerName.toUpperCase().replace(/-/g, '_');
  return `HUNTRESS_AUTH_${upper}`;
}

/**
 * Build the sandbox auth bundle for a session. Returns empty bundle when
 * the session is undefined (caller passes through to sandbox with `{}`).
 */
export function buildSessionEnv(session: AuthenticatedSession | undefined): SessionEnv {
  if (!session) {
    return { envVars: {}, curlrcContent: '', promptSummary: 'no active session' };
  }

  const envVars: Record<string, string> = {};
  const curlLines: string[] = ['silent', 'show-error'];
  const headerNames: string[] = [];

  for (const [name, value] of Object.entries(session.headers)) {
    if (!value) continue;
    // Rust validate_env rejects null-bytes and newlines — filter defensively.
    if (value.includes('\0') || /[\r\n]/.test(value)) continue;
    envVars[headerNameToEnvVar(name)] = value;
    curlLines.push(`header = "${name}: ${escapeCurlRcValue(value)}"`);
    headerNames.push(name);
  }

  if (session.cookies.length > 0) {
    const cookieStr = session.cookies
      .filter(c => c.name && c.value != null)
      .map(c => `${c.name}=${c.value}`)
      .join('; ');
    if (cookieStr) {
      envVars['HUNTRESS_AUTH_COOKIE'] = cookieStr;
      curlLines.push(`cookie = "${escapeCurlRcValue(cookieStr)}"`);
    }
  }

  if (session.csrfToken && !envVars['HUNTRESS_AUTH_CSRF_TOKEN']) {
    envVars['HUNTRESS_AUTH_CSRF_TOKEN'] = session.csrfToken;
    curlLines.push(`header = "X-CSRF-Token: ${escapeCurlRcValue(session.csrfToken)}"`);
  }

  const curlrcContent = curlLines.length > 2 ? curlLines.join('\n') + '\n' : '';
  const summary = describeSession(session, headerNames);

  return { envVars, curlrcContent, promptSummary: summary };
}

/** Produce a one-line description of the session for logs + the system prompt. */
export function describeSession(session: AuthenticatedSession, headerNames?: string[]): string {
  const names = headerNames ?? Object.keys(session.headers);
  const parts: string[] = [`label="${session.label}"`, `type=${session.authType}`];
  if (names.length > 0) parts.push(`headers=[${names.join(', ')}]`);
  if (session.cookies.length > 0) parts.push(`cookies=${session.cookies.length}`);
  if (session.csrfToken) parts.push('csrf=yes');
  return parts.join(' ');
}

/** Escape a value for inclusion inside a curlrc `"..."` quoted string. */
function escapeCurlRcValue(value: string): string {
  // curl config parser: backslash-escape only `"` and `\` inside quoted values.
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
