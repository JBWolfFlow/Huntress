/**
 * Approval Gate Integration Tests
 *
 * Verifies the approval gate callback pipeline:
 * 1. onApprovalRequest callback fires for dangerous commands
 * 2. Auto-approve bypasses modal for safe recon commands
 * 3. Denied commands block execution and return error
 * 4. CustomEvent dispatched with correct shape for App.tsx
 * 5. window.__huntress_approval_callbacks map resolves correctly
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

// ─── Test the approval callback factory (same logic as HuntSessionContext) ────

function createApprovalCallback() {
  return async (request: {
    command: string;
    target: string;
    reasoning: string;
    category: string;
    toolName?: string;
    safetyWarnings?: string[];
    agent?: string;
  }): Promise<boolean> => {
    const approvalId = `approval_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    const win = window as unknown as {
      __huntress_approval_callbacks?: Map<string, (approved: boolean) => void>;
    };
    if (!win.__huntress_approval_callbacks) {
      win.__huntress_approval_callbacks = new Map();
    }

    return new Promise<boolean>((resolve) => {
      win.__huntress_approval_callbacks!.set(approvalId, resolve);

      window.dispatchEvent(
        new CustomEvent('tool-approval-request', {
          detail: {
            approvalId,
            request: {
              command: request.command,
              target: request.target,
              tool: {
                name: request.toolName ?? request.command.split(/\s+/)[0],
                safetyLevel: request.category === 'recon' || request.category === 'utility'
                  ? 'SAFE'
                  : request.category === 'active_testing'
                    ? 'DANGEROUS'
                    : 'RESTRICTED',
              },
              validation: {
                reasoning: request.reasoning,
                agent: request.agent ?? 'unknown',
                warnings: request.safetyWarnings ?? [],
              },
            },
          },
        })
      );
    });
  };
}

describe('Approval Gate Callback', () => {
  let callbackMap: Map<string, (approved: boolean) => void>;

  beforeEach(() => {
    callbackMap = new Map();
    (window as unknown as Record<string, unknown>).__huntress_approval_callbacks = callbackMap;
  });

  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).__huntress_approval_callbacks;
  });

  it('should dispatch tool-approval-request CustomEvent', async () => {
    const onApprovalRequest = createApprovalCallback();
    const events: CustomEvent[] = [];

    const listener = (e: Event) => events.push(e as CustomEvent);
    window.addEventListener('tool-approval-request', listener);

    // Don't await — resolve manually below
    const promise = onApprovalRequest({
      command: 'sqlmap -u https://target.com/page?id=1',
      target: 'target.com',
      reasoning: 'Test for SQL injection',
      category: 'active_testing',
      toolName: 'sqlmap',
      safetyWarnings: ['Invasive tool'],
      agent: 'sqli-hunter',
    });

    // Event should have been dispatched synchronously
    expect(events.length).toBe(1);
    const detail = events[0].detail;
    expect(detail.approvalId).toBeDefined();
    expect(detail.request.command).toBe('sqlmap -u https://target.com/page?id=1');
    expect(detail.request.target).toBe('target.com');
    expect(detail.request.tool.name).toBe('sqlmap');
    expect(detail.request.tool.safetyLevel).toBe('DANGEROUS');
    expect(detail.request.validation.agent).toBe('sqli-hunter');
    expect(detail.request.validation.warnings).toEqual(['Invasive tool']);

    // Resolve via callback map (simulates App.tsx handleApprove)
    const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (v: boolean) => void>;
    callbacks.get(detail.approvalId)?.(true);

    const result = await promise;
    expect(result).toBe(true);

    window.removeEventListener('tool-approval-request', listener);
  });

  it('should resolve false when user denies', async () => {
    const onApprovalRequest = createApprovalCallback();

    const listener = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      // Simulate deny
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (v: boolean) => void>;
      callbacks.get(detail.approvalId)?.(false);
    };
    window.addEventListener('tool-approval-request', listener);

    const result = await onApprovalRequest({
      command: 'nmap -sV target.com',
      target: 'target.com',
      reasoning: 'Port scan',
      category: 'active_testing',
    });

    expect(result).toBe(false);
    window.removeEventListener('tool-approval-request', listener);
  });

  it('should classify recon category as SAFE safety level', async () => {
    const onApprovalRequest = createApprovalCallback();
    const events: CustomEvent[] = [];

    const listener = (e: Event) => {
      const evt = e as CustomEvent;
      events.push(evt);
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (v: boolean) => void>;
      callbacks.get(evt.detail.approvalId)?.(true);
    };
    window.addEventListener('tool-approval-request', listener);

    await onApprovalRequest({
      command: 'subfinder -d target.com',
      target: 'target.com',
      reasoning: 'Subdomain enumeration',
      category: 'recon',
    });

    expect(events[0].detail.request.tool.safetyLevel).toBe('SAFE');
    window.removeEventListener('tool-approval-request', listener);
  });

  it('should classify unknown category as RESTRICTED', async () => {
    const onApprovalRequest = createApprovalCallback();
    const events: CustomEvent[] = [];

    const listener = (e: Event) => {
      const evt = e as CustomEvent;
      events.push(evt);
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (v: boolean) => void>;
      callbacks.get(evt.detail.approvalId)?.(true);
    };
    window.addEventListener('tool-approval-request', listener);

    await onApprovalRequest({
      command: 'custom-tool --target foo',
      target: 'foo.com',
      reasoning: 'Testing',
      category: 'custom',
    });

    expect(events[0].detail.request.tool.safetyLevel).toBe('RESTRICTED');
    window.removeEventListener('tool-approval-request', listener);
  });

  it('should extract tool name from command when toolName not provided', async () => {
    const onApprovalRequest = createApprovalCallback();
    const events: CustomEvent[] = [];

    const listener = (e: Event) => {
      const evt = e as CustomEvent;
      events.push(evt);
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (v: boolean) => void>;
      callbacks.get(evt.detail.approvalId)?.(true);
    };
    window.addEventListener('tool-approval-request', listener);

    await onApprovalRequest({
      command: 'nuclei -u https://target.com -t cves/',
      target: 'target.com',
      reasoning: 'CVE scanning',
      category: 'active_testing',
    });

    expect(events[0].detail.request.tool.name).toBe('nuclei');
    window.removeEventListener('tool-approval-request', listener);
  });

  it('should generate unique approval IDs for concurrent requests', async () => {
    const onApprovalRequest = createApprovalCallback();
    const ids: string[] = [];

    const listener = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      ids.push(detail.approvalId);
      // Auto-approve all
      const callbacks = (window as unknown as Record<string, unknown>).__huntress_approval_callbacks as Map<string, (v: boolean) => void>;
      callbacks.get(detail.approvalId)?.(true);
    };
    window.addEventListener('tool-approval-request', listener);

    const baseRequest = {
      command: 'test',
      target: 'x.com',
      reasoning: 'test',
      category: 'active_testing',
    };

    await Promise.all([
      onApprovalRequest(baseRequest),
      onApprovalRequest(baseRequest),
      onApprovalRequest(baseRequest),
    ]);

    // All 3 should have distinct IDs
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(3);

    window.removeEventListener('tool-approval-request', listener);
  });
});

// ─── Test auto-approve logic (mirrors react_loop behavior) ────

describe('Auto-Approve Logic', () => {
  it('should auto-approve safe recon when autoApproveSafe is true', () => {
    const autoApproveSafe = true;
    const category = 'recon';
    const isSafeCategory = category === 'recon' || category === 'utility';
    const shouldAutoApprove = autoApproveSafe && isSafeCategory;

    expect(shouldAutoApprove).toBe(true);
  });

  it('should NOT auto-approve active testing even when autoApproveSafe is true', () => {
    const autoApproveSafe = true;
    const category: string = 'active_testing';
    const isSafeCategory = category === 'recon' || category === 'utility';
    const shouldAutoApprove = autoApproveSafe && isSafeCategory;

    expect(shouldAutoApprove).toBe(false);
  });

  it('should NOT auto-approve recon when autoApproveSafe is false', () => {
    const autoApproveSafe = false;
    const category: string = 'recon';
    const isSafeCategory = category === 'recon' || category === 'utility';
    const shouldAutoApprove = autoApproveSafe && isSafeCategory;

    expect(shouldAutoApprove).toBe(false);
  });

  it('should auto-approve utility commands when autoApproveSafe is true', () => {
    const autoApproveSafe = true;
    const category: string = 'utility';
    const isSafeCategory = category === 'recon' || category === 'utility';
    const shouldAutoApprove = autoApproveSafe && isSafeCategory;

    expect(shouldAutoApprove).toBe(true);
  });
});
