# Domain Firewall Examples

## CLI Examples

### Example 1: Lock agent to specific domains

```bash
# Only allow Stripe docs and GitHub — block everything else
node domain-firewall.mjs --session-id $SID \
  --allowlist "docs.stripe.com,stripe.com,github.com" \
  --default deny
```

Output:
```
[14:30:01] ALLOWED  docs.stripe.com          (allowlist)
[14:30:05] BLOCKED evil.com                  (default)
[14:30:08] ALLOWED  stripe.com               (allowlist)
```

### Example 2: Block known-bad, allow everything else

```bash
# Permissive mode — only block specific threats
node domain-firewall.mjs --session-id $SID \
  --denylist "evil.com,phishing-site.com,malware.download" \
  --default allow
```

### Example 3: Local Chrome with honeypot test

```bash
# Start Chrome
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 --headless=new about:blank &

# Get CDP URL
CDP_URL=$(curl -s http://localhost:9222/json/version | jq -r .webSocketDebuggerUrl)

# Start firewall — only allow localhost
node domain-firewall.mjs --cdp-url "$CDP_URL" \
  --allowlist "localhost" --default deny

# In another terminal, navigate:
#   localhost:8080 → ALLOWED
#   127.0.0.1:9090 → BLOCKED (different hostname)
#   evil.com → BLOCKED
```

### Example 4: JSON logging for post-session analysis

```bash
# Run firewall with JSON output
node domain-firewall.mjs --session-id $SID \
  --allowlist "example.com" --default deny --json > firewall.log &

# ... agent browses ...

# Analyze blocked navigations
cat firewall.log | jq 'select(.action == "BLOCKED")'

# Count blocks per domain
cat firewall.log | jq -r 'select(.action == "BLOCKED") | .domain' | sort | uniq -c | sort -rn
```

### Example 5: Protect a browse CLI session

```bash
# Create session
SESSION_ID=$(bb sessions create --body '{"projectId":"...","keepAlive":true}' | jq -r .id)

# Enable firewall in background
node domain-firewall.mjs --session-id $SESSION_ID \
  --allowlist "docs.stripe.com,stripe.com" --default deny &

# Browse normally — firewall is transparent
browse open https://docs.stripe.com --session-id $SESSION_ID
browse snapshot
# ... agent works ...

# Malicious navigation from page content → automatically blocked
```

---

## Code Integration Examples (TypeScript API)

For developers embedding the firewall directly in Stagehand projects.

### Example 6: Basic Allowlist

```typescript
import { Stagehand } from "@browserbasehq/stagehand";
import { installDomainFirewall, allowlist } from "./domain-firewall";

const stagehand = new Stagehand({ env: "BROWSERBASE" });
await stagehand.init();
const page = stagehand.context.pages()[0];

await installDomainFirewall(page, {
  policies: [
    allowlist(["wikipedia.org", "en.wikipedia.org", "github.com"]),
  ],
  defaultVerdict: "deny",
});

await page.goto("https://en.wikipedia.org/wiki/Node.js");        // allowed
await page.goto("https://example.com").catch(() => "blocked");    // blocked

await stagehand.close();
```

### Example 7: Human-in-the-Loop Approval (stdin)

```typescript
import * as readline from "readline/promises";
import { installDomainFirewall, allowlist, interactive } from "./domain-firewall";

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

await installDomainFirewall(page, {
  policies: [
    allowlist(["en.wikipedia.org"]),
    interactive(
      async (req) => {
        console.log(`\n  Agent wants to visit: ${req.domain} (${req.url})`);
        const answer = await rl.question("  Allow? (y/n): ");
        return answer.trim().toLowerCase().startsWith("y") ? "allow" : "deny";
      },
      { timeoutMs: 60000, onTimeout: "deny" },
    ),
  ],
  defaultVerdict: "deny",
});

// Wikipedia: instant (allowlist). Unknown domain: held → terminal prompts → you decide.
rl.close();
```

### Example 8: Full Policy Chain

```typescript
import {
  installDomainFirewall,
  denylist, allowlist, tld, pattern, interactive,
  type AuditEntry,
} from "./domain-firewall";

const auditLog: AuditEntry[] = [];

await installDomainFirewall(page, {
  policies: [
    denylist(["evil.com", "phishing-site.com"]),                     // 1. block known-bad
    allowlist(["github.com", "docs.google.com"]),                    // 2. allow known-good
    pattern(["*.github.com", "*.githubusercontent.com"], "allow"),   // 3. GitHub subdomains
    tld({ ".org": "allow", ".edu": "allow", ".gov": "allow" }),     // 4. trusted TLDs
    pattern(["*.ru", "*.cn", "*.tk"], "deny"),                       // 5. suspicious TLDs
    interactive(promptUser, { timeoutMs: 60000, onTimeout: "deny" }),// 6. ask human
  ],
  defaultVerdict: "deny",
  auditLog,
});
```

## Tips

- **Policy order is your security model**: denylists first (fail-fast), then allowlists, then broad rules, then interactive as fallback.
- **Subdomain coverage**: `allowlist(["github.com"])` does NOT match `api.github.com`. Use `pattern(["*.github.com"], "allow")` or list subdomains explicitly in the CLI `--allowlist`.
- **Start the firewall before browsing**: install before the first navigation so all requests are intercepted.
- **Audit log**: in code mode, pass `auditLog: []` and check `decidedBy` to see which policy made each decision. In CLI mode, use `--json` and pipe to `jq`.
