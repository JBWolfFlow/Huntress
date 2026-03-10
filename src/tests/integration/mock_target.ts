/**
 * Mock Target Server for Integration Testing
 *
 * In-process HTTP server simulating common vulnerability patterns.
 * Provides configurable routes for testing validators and agents
 * without hitting external systems.
 */

import http from 'http';

export interface MockTargetConfig {
  port?: number;
}

export class MockTargetServer {
  private server: http.Server | null = null;
  private port: number;
  private actualPort: number = 0;

  constructor(config: MockTargetConfig = {}) {
    this.port = config.port ?? 0; // 0 = let OS pick a free port
  }

  /** Start the server and return the base URL */
  async start(): Promise<string> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        const addr = this.server!.address();
        if (addr && typeof addr !== 'string') {
          this.actualPort = addr.port;
          resolve(`http://127.0.0.1:${addr.port}`);
        } else {
          reject(new Error('Failed to get server address'));
        }
      });

      this.server.on('error', reject);
    });
  }

  /** Stop the server */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /** Get the server's port */
  getPort(): number {
    return this.actualPort;
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const path = url.pathname;

    // CORS headers for all responses
    res.setHeader('Access-Control-Allow-Origin', '*');

    switch (path) {
      case '/':
        this.handleIndex(res);
        break;
      case '/xss':
        this.handleXss(url, res);
        break;
      case '/sqli':
        this.handleSqli(url, res);
        break;
      case '/ssrf':
        this.handleSsrf(url, res);
        break;
      case '/ssti':
        this.handleSsti(url, res);
        break;
      case '/cmd':
        this.handleCommandInjection(url, res);
        break;
      case '/traversal':
        this.handlePathTraversal(url, res);
        break;
      case '/clean':
        this.handleClean(res);
        break;
      case '/api/users':
        this.handleApiUsers(url, res);
        break;
      default:
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
  }

  private handleIndex(res: http.ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Mock Target</h1></body></html>');
  }

  /** Reflected XSS: echoes the q parameter without sanitization */
  private handleXss(url: URL, res: http.ServerResponse): void {
    const q = url.searchParams.get('q') ?? '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body><h1>Search Results</h1><p>You searched for: ${q}</p></body></html>`);
  }

  /** SQL injection: returns error message when special chars detected */
  private handleSqli(url: URL, res: http.ServerResponse): void {
    const id = url.searchParams.get('id') ?? '';

    // Simulate SQL error on injection attempts
    if (id.includes("'") || id.includes('"') || id.includes('--') || id.includes(' OR ')) {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(
        `<html><body><h1>Error</h1>` +
        `<p>You have an error in your SQL syntax; check the manual that corresponds ` +
        `to your MySQL server version for the right syntax to use near '${id}' at line 1</p>` +
        `</body></html>`,
      );
      return;
    }

    // Normal response for clean input
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: parseInt(id, 10) || 0, name: 'Test User', email: 'test@example.com' }));
  }

  /** SSRF: follows the url parameter and returns the content */
  private handleSsrf(url: URL, res: http.ServerResponse): void {
    const target = url.searchParams.get('url') ?? '';

    if (!target) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>URL Preview</h1><form><input name="url"/></form></body></html>');
      return;
    }

    // Simulate fetching internal resources
    if (target.includes('127.0.0.1') || target.includes('localhost') || target.includes('169.254.169.254')) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`Fetched content from ${target}:\n{"internal": true, "data": "sensitive_internal_data"}`);
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`Fetched content from ${target}:\n<html><body>External page</body></html>`);
  }

  /** SSTI: evaluates template expressions */
  private handleSsti(url: URL, res: http.ServerResponse): void {
    let name = url.searchParams.get('name') ?? 'World';

    // Simulate Jinja2-like template evaluation
    if (name === '{{7*7}}') {
      name = '49';
    } else if (name === "{{7*'7'}}") {
      name = '7777777';
    } else if (name.startsWith('{{') && name.endsWith('}}')) {
      // Generic template expression — return as-is to simulate no injection
      // unless it matches known patterns
      name = name;
    }

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
  }

  /** Command injection: executes via simulated shell */
  private handleCommandInjection(url: URL, res: http.ServerResponse): void {
    const input = url.searchParams.get('input') ?? '';

    // Simulate command injection vulnerability
    if (input.includes(';') || input.includes('|') || input.includes('`') || input.includes('$(')) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(
        `ping result for ${input}\n` +
        `uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)\n` +
        `root:x:0:0:root:/root:/bin/bash\n`,
      );
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`ping result for ${input}\nPING ${input} (1.2.3.4) 56(84) bytes of data.`);
  }

  /** Path traversal: serves files based on the file parameter */
  private handlePathTraversal(url: URL, res: http.ServerResponse): void {
    const file = url.searchParams.get('file') ?? '';

    // Simulate path traversal vulnerability
    if (file.includes('..')) {
      if (file.includes('/etc/passwd')) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin');
        return;
      }
      if (file.includes('/etc/shadow')) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('root:$6$rounds=656000$hash:19000:0:99999:7:::');
        return;
      }
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`Contents of ${file}:\nThis is a normal file.`);
  }

  /** Clean endpoint — no vulnerabilities, for false-positive testing */
  private handleClean(res: http.ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Clean Page</h1><p>No vulnerabilities here.</p></body></html>');
  }

  /** API endpoint for IDOR testing */
  private handleApiUsers(url: URL, res: http.ServerResponse): void {
    const id = url.searchParams.get('id');
    if (!id) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ id: 1, name: 'Current User' }]));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: parseInt(id, 10), name: `User ${id}`, email: `user${id}@example.com` }));
  }
}
