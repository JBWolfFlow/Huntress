/**
 * Auth Browser Capture — Unit Tests (Phase B)
 *
 * Verifies:
 * 1. CapturedAuth type structure
 * 2. AuthBrowserCapture class instantiation
 * 3. Cleanup is safe to call without prior launch
 * 4. Module exports correct types
 */

import { describe, it, expect } from 'vitest';
import type { CapturedAuth, CapturedCookie, CaptureStatus } from './auth_browser_capture';

describe('AuthBrowserCapture — types', () => {
  it('CapturedAuth has correct shape', () => {
    const auth: CapturedAuth = {
      bearerToken: 'test-token',
      cookies: [],
      customHeaders: { 'wallet-authorization': 'abc123' },
      finalUrl: 'https://example.com/dashboard',
      localStorage: { key: 'value' },
      sessionStorage: {},
    };
    expect(auth.bearerToken).toBe('test-token');
    expect(auth.cookies).toHaveLength(0);
    expect(auth.customHeaders['wallet-authorization']).toBe('abc123');
    expect(auth.finalUrl).toBe('https://example.com/dashboard');
  });

  it('CapturedAuth works without optional bearerToken', () => {
    const auth: CapturedAuth = {
      cookies: [{ name: 'session', value: 'abc', domain: '.example.com', path: '/', httpOnly: true, secure: true }],
      customHeaders: {},
      finalUrl: 'https://example.com',
      localStorage: {},
      sessionStorage: {},
    };
    expect(auth.bearerToken).toBeUndefined();
    expect(auth.cookies).toHaveLength(1);
    expect(auth.cookies[0].name).toBe('session');
  });

  it('CapturedCookie has correct fields', () => {
    const cookie: CapturedCookie = {
      name: 'auth_session',
      value: 'xyz789',
      domain: '.walletbot.me',
      path: '/',
      httpOnly: true,
      secure: true,
    };
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
  });

  it('CaptureStatus union covers all phases', () => {
    const statuses: CaptureStatus[] = [
      { phase: 'launching', message: 'Starting...' },
      { phase: 'waiting', message: 'Log in...' },
      { phase: 'captured', message: 'Got tokens' },
      { phase: 'error', message: 'Failed' },
      { phase: 'timeout', message: 'Timed out' },
    ];
    expect(statuses).toHaveLength(5);
    expect(statuses.map(s => s.phase)).toEqual(['launching', 'waiting', 'captured', 'error', 'timeout']);
  });
});

describe('AuthBrowserCapture — class', () => {
  it('can be instantiated', async () => {
    const { AuthBrowserCapture } = await import('./auth_browser_capture');
    const capture = new AuthBrowserCapture();
    expect(capture).toBeDefined();
    expect(typeof capture.captureAuth).toBe('function');
    expect(typeof capture.cleanup).toBe('function');
  });

  it('cleanup is safe to call without prior launch', async () => {
    const { AuthBrowserCapture } = await import('./auth_browser_capture');
    const capture = new AuthBrowserCapture();
    await capture.cleanup();
    await capture.cleanup();
  });

  it('cleanup can be called multiple times', async () => {
    const { AuthBrowserCapture } = await import('./auth_browser_capture');
    const capture = new AuthBrowserCapture();
    await capture.cleanup();
    await capture.cleanup();
    await capture.cleanup();
  });
});
