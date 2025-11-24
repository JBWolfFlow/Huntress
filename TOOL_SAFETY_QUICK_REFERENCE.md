# Tool Safety Quick Reference

## 🚦 Safety Level Quick Guide

| Level | Badge | Risk | Approval | Rate Limit | Example Tools |
|-------|-------|------|----------|------------|---------------|
| **SAFE** | ✅ | None | No | No | subfinder, waybackurls, gau |
| **CONTROLLED** | ⚠️ | Low | Yes | 5-10/s | nuclei, ffuf, feroxbuster |
| **RESTRICTED** | 🔶 | Medium | Yes + Enable | 2-5/s | sqlmap, dirsearch, arjun |
| **BLOCKED** | 🚫 | High | N/A | N/A | hydra, medusa, nmap -sS |
| **FORBIDDEN** | ⛔ | Critical | N/A | N/A | slowloris, goldeneye |

## ✅ SAFE Tools (Always Allowed)

```bash
# Subdomain enumeration
subfinder -d example.com
amass enum -passive -d example.com

# URL discovery
waybackurls example.com
gau example.com

# HTTP probing
httpx -l targets.txt
```

## ⚠️ CONTROLLED Tools (Requires Approval)

```bash
# Vulnerability scanning (auto rate-limited to 5/s)
nuclei -u https://example.com -rl 5

# Directory fuzzing (auto rate-limited to 10/s)
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 10

# Content discovery (auto rate-limited to 10/s)
feroxbuster -u https://example.com --rate-limit 10

# Web crawling (auto rate-limited to 5/s)
katana -u https://example.com
```

## 🔶 RESTRICTED Tools (Requires Medium Mode)

```bash
# SQL injection testing (MUST use --level 1 --risk 1)
sqlmap -u "https://example.com/page?id=1" --level 1 --risk 1 --batch

# Directory scanning
dirsearch -u https://example.com

# Parameter discovery
arjun -u https://example.com
```

**To enable:** `toolInterface.enableMediumMode()`

## 🚫 BLOCKED Tools (Never Allowed)

```bash
# Password brute-forcing - INSTANT BAN RISK
hydra -l admin -P passwords.txt  # ❌ BLOCKED
medusa -h example.com            # ❌ BLOCKED

# Aggressive network scanning
nmap -sS example.com             # ❌ BLOCKED
nmap -sU example.com             # ❌ BLOCKED

# Exploitation frameworks
msfconsole                       # ❌ BLOCKED
```

## ⛔ FORBIDDEN Tools (Should Not Exist)

```bash
# DoS attack tools - LEGAL THREAT + INSTANT BAN
slowloris example.com            # ⛔ DELETE FROM SYSTEM
goldeneye example.com            # ⛔ DELETE FROM SYSTEM
hulk example.com                 # ⛔ DELETE FROM SYSTEM
```

## 🚨 Dangerous Flags (Auto-Blocked)

### Amass
```bash
amass enum -active    # ❌ Active scanning
amass enum -brute     # ❌ Brute forcing
```

### SQLMap
```bash
sqlmap --os-shell     # ❌ OS command execution
sqlmap --sql-shell    # ❌ SQL shell
sqlmap --level 5      # ❌ Too aggressive
sqlmap --risk 3       # ❌ Too risky
```

### Nmap
```bash
nmap -sS              # ❌ SYN scan
nmap -sU              # ❌ UDP scan
nmap -sN              # ❌ NULL scan
nmap -sF              # ❌ FIN scan
```

### FFuf/Feroxbuster
```bash
ffuf -rate 0          # ❌ No rate limit
ffuf -t 1000          # ❌ Too many threads
feroxbuster --rate-limit 0  # ❌ No rate limit
```

## 📊 Rate Limits by Tool

| Tool | Max Req/s | Window |
|------|-----------|--------|
| nuclei | 5 | 1s |
| ffuf | 10 | 1s |
| feroxbuster | 10 | 1s |
| katana | 5 | 1s |
| sqlmap | 2 | 1s |
| dirsearch | 5 | 1s |
| arjun | 5 | 1s |

## 🔄 Typical Workflow

### 1. Passive Recon (No Approval)
```typescript
// Discover subdomains
await toolInterface.executeTool(
  'recon_agent',
  'subfinder -d example.com',
  'example.com',
  true  // Skip approval for SAFE tools
);
```

### 2. Active Scanning (Requires Approval)
```typescript
// Scan for vulnerabilities
await toolInterface.executeTool(
  'vuln_scanner',
  'nuclei -u https://example.com -t cves/',
  'example.com',
  false  // Requires approval
);
// → User sees approval modal
// → If approved, executes with rate limiting
```

### 3. Medium Mode Testing (Requires Enable)
```typescript
// Enable medium mode
toolInterface.enableMediumMode();

// Test for SQL injection
await toolInterface.executeTool(
  'sql_hunter',
  'sqlmap -u "https://example.com/page?id=1" --level 1',
  'example.com',
  false
);
```

## 🛡️ Safety Checklist

Before executing any tool:

- [ ] Tool is registered in the system
- [ ] Target is in authorized scope
- [ ] Rate limits are configured
- [ ] Dangerous flags are not present
- [ ] Human approval obtained (if required)
- [ ] Medium mode enabled (if RESTRICTED)
- [ ] Kill switch is not active
- [ ] Execution will be logged

## 🚨 Emergency Stop

```typescript
// Activate kill switch
await invoke('activate_kill_switch', {
  reason: 'scope_violation',
  context: 'Detected unauthorized testing'
});

// All operations immediately halt
```

## 📈 Monitoring

```typescript
// Check execution statistics
const stats = executor.getStatistics();
console.log('Blocked:', stats.blocked);
console.log('Successful:', stats.successful);

// Review audit logs
const logger = getGlobalAuditLogger();
const blocked = logger.query({ result: 'blocked' });
```

## ⚠️ Common Mistakes to Avoid

1. **Skipping approval for CONTROLLED tools** → Will be blocked
2. **Using RESTRICTED tools without Medium Mode** → Will be blocked
3. **Adding dangerous flags** → Will be blocked
4. **Testing out-of-scope targets** → Will be blocked + logged
5. **Exceeding rate limits** → Will be throttled
6. **Ignoring kill switch** → All operations halt

## 💡 Pro Tips

- Start with SAFE tools for reconnaissance
- Only enable Medium Mode when necessary
- Monitor rate limits to avoid throttling
- Review audit logs regularly
- Keep kill switch accessible
- Test in safe environment first
- Export logs for compliance

## 📚 Full Documentation

See [`AI_HUNT_EXECUTION_SYSTEM.md`](./AI_HUNT_EXECUTION_SYSTEM.md) for complete documentation.