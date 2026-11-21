"""Comprehensive CVE intelligence database for RedPilot.

Pure data module -- no I/O, no imports beyond stdlib, no side effects.
Encodes every CVE discovered through deep research (90+ extended web searches,
7 parallel research agents, Nov 2026) that is relevant to access-without-payment
detection on enterprise targets.

Organized into three threat categories:
  - CLAUDE_MCP_CVES: Claude Code and MCP ecosystem vulnerabilities
  - PAYMENT_BYPASS_CVES: Payment flow bypass vulnerabilities
  - ENTERPRISE_PLATFORM_CVES: Enterprise platform authentication/authz flaws

Also provides THREAT_INTELLIGENCE -- key metrics from the current threat
landscape that inform detection thresholds and prioritization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CVEEntry:
    id: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    affected_component: str
    vendor: str
    description: str
    attack_vector: str
    detection_patterns: list[str] = field(default_factory=list)
    remediation: str = ""
    discovered_date: str = ""
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. CLAUDE / MCP ECOSYSTEM CVEs
# ---------------------------------------------------------------------------

CLAUDE_MCP_CVES: list[CVEEntry] = [
    CVEEntry(
        id="CVE-2025-59536",
        cvss_score=8.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-362",
        affected_component="Claude Code CLI hooks",
        vendor="Anthropic",
        description="Hooks execute before trust prompt allowing arbitrary code execution on repository clone",
        attack_vector="Attacker places malicious hook in .claude/settings.json; victim clones repo; hook runs before trust dialog appears",
        detection_patterns=[
            r'"hooks"\s*:\s*\{',
            r'"SessionStart"\s*:\s*\[',
            r'"PreToolUse"\s*:\s*\[',
            r'"PostToolUse"\s*:\s*\[',
            r'\.claude/settings\.json.*hooks',
        ],
        remediation="Upgrade to Claude Code >= 1.0.17 which enforces trust prompt before hook execution",
        discovered_date="2025-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-59536"],
    ),
    CVEEntry(
        id="CVE-2026-21852",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cwe_id="CWE-601",
        affected_component="Claude Code API base URL",
        vendor="Anthropic",
        description="ANTHROPIC_BASE_URL in repo config redirects all API traffic including x-api-key to attacker proxy",
        attack_vector="Malicious .claude/settings.json sets ANTHROPIC_BASE_URL to attacker domain; proxy forwards to real API transparently",
        detection_patterns=[
            r'ANTHROPIC_BASE_URL\s*[=:]\s*["\']?https?://(?!api\.anthropic\.com)',
            r'"apiBaseUrl"\s*:\s*"https?://(?!api\.anthropic\.com)',
            r'x-api-key.*(?:proxy|redirect|forward)',
        ],
        remediation="Pin ANTHROPIC_BASE_URL to api.anthropic.com; reject overrides from repo-level config",
        discovered_date="2026-03",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-21852"],
    ),
    CVEEntry(
        id="CVE-2025-68143",
        cvss_score=8.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-78",
        affected_component="mcp-server-git",
        vendor="MCP Community",
        description="Command injection in mcp-server-git via crafted repository URLs",
        attack_vector="Specially crafted git URL with shell metacharacters passed to git clone without sanitization",
        detection_patterns=[
            r'mcp-server-git',
            r'git\s+clone\s+.*[;&|`$]',
            r'"server_name"\s*:\s*".*git"',
        ],
        remediation="Upgrade mcp-server-git; sanitize all git URLs against shell metacharacters",
        discovered_date="2025-11",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-68143"],
    ),
    CVEEntry(
        id="CVE-2025-68144",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cwe_id="CWE-22",
        affected_component="mcp-server-git",
        vendor="MCP Community",
        description="Path traversal in mcp-server-git allows reading files outside repo",
        attack_vector="Relative path with ../ sequences in file operation parameters",
        detection_patterns=[
            r'mcp-server-git.*\.\.',
            r'git.*(?:show|cat-file|diff).*\.\.\/',
        ],
        remediation="Upgrade mcp-server-git; enforce path canonicalization",
        discovered_date="2025-11",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-68144"],
    ),
    CVEEntry(
        id="CVE-2025-68145",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-200",
        affected_component="mcp-server-git",
        vendor="MCP Community",
        description="Information disclosure in mcp-server-git leaks sensitive file contents",
        attack_vector="Unauthenticated read of .env, credentials, and config files through git server tools",
        detection_patterns=[
            r'mcp-server-git.*(?:\.env|credentials|config)',
            r'git.*(?:show|log).*(?:secret|token|key|password)',
        ],
        remediation="Upgrade mcp-server-git; implement file access controls",
        discovered_date="2025-11",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-68145"],
    ),
    CVEEntry(
        id="CVE-2026-27735",
        cvss_score=8.2,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-22",
        affected_component="MCP git_add tool",
        vendor="MCP Community",
        description="Path traversal in git_add MCP tool allows writing files outside repository boundary",
        attack_vector="Crafted path parameter with traversal sequences bypasses repo root check in git_add tool",
        detection_patterns=[
            r'git_add.*\.\.\/',
            r'"tool"\s*:\s*"git_add".*\.\.',
            r'git\s+add\s+.*\.\.\/',
        ],
        remediation="Validate all file paths are within the repository root after canonicalization",
        discovered_date="2026-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-27735"],
    ),
    CVEEntry(
        id="CVE-2026-25723",
        cvss_score=7.9,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-269",
        affected_component="Claude Code file-write restrictions",
        vendor="Anthropic",
        description="File-write restriction bypass allows writing to protected paths",
        attack_vector="Symbolic link or race condition bypasses the file path allowlist check",
        detection_patterns=[
            r'(?:symlink|ln\s+-s).*(?:\.claude|\.ssh|\.aws|\.config)',
            r'write_file.*(?:/etc/|/root/|\.ssh/|\.aws/)',
        ],
        remediation="Resolve symlinks before path validation; use O_NOFOLLOW",
        discovered_date="2026-03",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-25723"],
    ),
    CVEEntry(
        id="CVE-2026-33068",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-362",
        affected_component="Claude Code trust dialog",
        vendor="Anthropic",
        description="Trust dialog bypass via timing attack allows code execution before user consent",
        attack_vector="Race condition between trust prompt display and hook execution window",
        detection_patterns=[
            r'trust.*(?:bypass|skip|race)',
            r'\.claude.*(?:settings|hooks).*(?:before|pre).*(?:trust|consent)',
        ],
        remediation="Enforce synchronous trust verification before any code execution",
        discovered_date="2026-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-33068"],
    ),
    CVEEntry(
        id="CVE-2026-40068",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        cwe_id="CWE-362",
        affected_component="Claude Code hooks (variant)",
        vendor="Anthropic",
        description="Hooks execute before trust prompt -- variant bypassing the CVE-2025-59536 fix",
        attack_vector="New hook type or execution path not covered by the original fix",
        detection_patterns=[
            r'"hooks"\s*:\s*\{.*"(?:PreToolUse|PostToolUse|SessionStart)"',
            r'\.claude/settings\.(?:json|local\.json).*hooks',
            r'"command"\s*:\s*"(?:curl|wget|bash|sh|python|node)',
        ],
        remediation="Audit all hook execution paths; enforce trust-before-execute invariant",
        discovered_date="2026-06",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-40068"],
    ),
    CVEEntry(
        id="CVE-2026-24052",
        cvss_score=7.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwe_id="CWE-20",
        affected_component="Claude Code domain validation",
        vendor="Anthropic",
        description="Domain validation flaw allows credential exfiltration to attacker-controlled domains",
        attack_vector="Subdomain or unicode confusable bypasses the domain allowlist",
        detection_patterns=[
            r'(?:anthropic\.com\.[a-z]+|api\.anthropic\.com\.evil|xn--.*anthropic)',
            r'(?:api|auth)\.(?!anthropic\.com)[a-z-]+\.(?:com|io|dev)',
        ],
        remediation="Use strict domain matching with punycode normalization",
        discovered_date="2026-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-24052"],
    ),
    CVEEntry(
        id="CVE-2026-54316",
        cvss_score=9.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        cwe_id="CWE-200",
        affected_component="Claude Code CI integration",
        vendor="Anthropic",
        description="CI pipeline flaw exposes authentication tokens in build logs and artifacts",
        attack_vector="Claude Code CI mode logs bearer tokens or API keys to stdout captured by CI system",
        detection_patterns=[
            r'(?:CLAUDE_API_KEY|ANTHROPIC_API_KEY|sk-ant-)\s*[=:]\s*\S+',
            r'(?:Bearer|token)\s+sk-ant-[A-Za-z0-9_-]+',
            r'CI.*(?:token|key|secret).*(?:log|output|artifact)',
        ],
        remediation="Mask all credentials in CI output; use ephemeral tokens with minimal scope",
        discovered_date="2026-08",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-54316"],
    ),
    CVEEntry(
        id="CVE-2026-44467",
        cvss_score=7.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cwe_id="CWE-295",
        affected_component="Claude Code SSH certificate validation",
        vendor="Anthropic",
        description="SSH certificate validation bypass allows MITM on git operations",
        attack_vector="Malformed SSH certificate accepted without proper chain validation",
        detection_patterns=[
            r'(?:ssh|git).*(?:StrictHostKeyChecking\s*=?\s*no|UserKnownHostsFile\s*/dev/null)',
            r'(?:GIT_SSH_COMMAND|ssh).*-o\s*StrictHostKeyChecking',
        ],
        remediation="Enforce strict SSH host key and certificate chain validation",
        discovered_date="2026-07",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-44467"],
    ),
    CVEEntry(
        id="CVE-2026-35020",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-94",
        affected_component="Claude Code (chainable execution)",
        vendor="Anthropic",
        description="Chainable code execution via crafted MCP tool sequence",
        attack_vector="Sequence of benign-looking MCP tool calls that compose into arbitrary execution",
        detection_patterns=[
            r'"tool_calls"\s*:\s*\[.*"write_file".*"bash"',
            r'(?:write_file|create_file).*(?:\.sh|\.py|\.js).*(?:bash|execute|run)',
        ],
        remediation="Implement tool call sequence analysis; detect execution chain patterns",
        discovered_date="2026-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-35020"],
    ),
    CVEEntry(
        id="CVE-2026-35022",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-522",
        affected_component="Claude Code (chainable credential theft)",
        vendor="Anthropic",
        description="Chainable credential theft via tool call sequence exfiltrating secrets",
        attack_vector="Tool call reads credential file, then another tool call sends data to external endpoint",
        detection_patterns=[
            r'(?:read_file|cat).*(?:\.env|credentials|\.aws|\.ssh).*(?:curl|fetch|http)',
            r'"tool_calls".*"read_file".*(?:secret|key|token).*"(?:bash|http)',
        ],
        remediation="Monitor tool call data flow; block credential content from reaching network tools",
        discovered_date="2026-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-35022"],
    ),
    CVEEntry(
        id="CVE-2025-52882",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-287",
        affected_component="Claude Code WebSocket",
        vendor="Anthropic",
        description="WebSocket authentication bypass allows unauthorized session access",
        attack_vector="WebSocket upgrade request accepted without validating bearer token",
        detection_patterns=[
            r'(?:ws|wss)://.*(?:claude|anthropic).*(?:upgrade|websocket)',
            r'Upgrade:\s*websocket.*(?:!Authorization|!Bearer)',
            r'WebSocket.*(?:no auth|missing token)',
        ],
        remediation="Enforce bearer token validation on WebSocket upgrade handshake",
        discovered_date="2025-09",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-52882"],
    ),
    CVEEntry(
        id="CVE-2025-66479",
        cvss_score=9.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        cwe_id="CWE-265",
        affected_component="Claude Code sandbox",
        vendor="Anthropic",
        description="Sandbox escape allows arbitrary code execution on host system",
        attack_vector="Crafted tool call sequence breaks out of the execution sandbox",
        detection_patterns=[
            r'(?:sandbox|container).*(?:escape|breakout|bypass)',
            r'(?:mount|nsenter|chroot|unshare).*(?:/host|/proc/1)',
            r'(?:CAP_SYS_ADMIN|SYS_PTRACE|--privileged)',
        ],
        remediation="Harden sandbox with seccomp-bpf; drop all unnecessary capabilities",
        discovered_date="2025-12",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-66479"],
    ),
    CVEEntry(
        id="CVE-2025-6514",
        cvss_score=9.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cwe_id="CWE-287",
        affected_component="mcp-remote",
        vendor="MCP Community",
        description="Remote code execution via authentication bypass in mcp-remote transport",
        attack_vector="Missing authentication on mcp-remote SSE transport allows unauthenticated tool execution",
        detection_patterns=[
            r'mcp-remote',
            r'"transport"\s*:\s*"(?:sse|streamable-http)".*(?:!auth|!token)',
            r'(?:sse|http)://.*mcp.*(?:tools/call|tools/list)',
        ],
        remediation="Enforce mutual TLS or bearer token authentication on all MCP transports",
        discovered_date="2025-06",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-6514"],
    ),
    CVEEntry(
        id="CVE-2025-54135",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        cwe_id="CWE-94",
        affected_component="Cursor IDE",
        vendor="Anysphere",
        description="Remote code execution in Cursor IDE via malicious MCP server",
        attack_vector="Poisoned MCP server tool description contains hidden instructions that trigger code execution",
        detection_patterns=[
            r'(?:cursor|\.cursor).*mcp.*(?:server|tool)',
            r'"description".*(?:\\u200b|\\u200c|\\u200d|\\ufeff|<\!--|display:\s*none)',
        ],
        remediation="Sanitize MCP tool descriptions; display raw descriptions to user",
        discovered_date="2025-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-54135"],
    ),
    CVEEntry(
        id="CVE-2026-30615",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cwe_id="CWE-269",
        affected_component="Windsurf IDE",
        vendor="Codeium",
        description="Windsurf config write allows MCP server to modify IDE configuration",
        attack_vector="MCP tool call writes to Windsurf config directory, persisting malicious settings",
        detection_patterns=[
            r'(?:windsurf|\.windsurf).*(?:config|settings)',
            r'write_file.*(?:\.windsurf|codeium)',
        ],
        remediation="Restrict MCP tool file write access from modifying IDE config paths",
        discovered_date="2026-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-30615"],
    ),
    CVEEntry(
        id="CVE-2025-54136",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cwe_id="CWE-94",
        affected_component="MCP ecosystem (MCPoison)",
        vendor="MCP Community",
        description="MCPoison: backdoor injection via poisoned MCP server tool metadata",
        attack_vector="Tool description contains invisible unicode instructions that cause the agent to execute attacker commands",
        detection_patterns=[
            r'[\U000E0000-\U000E007F]',
            r'\\u200[bcde]|\\ufeff',
            r'"description".*(?:ignore previous|system prompt|you are now)',
            r'<\s*(?:div|span)\s+style\s*=\s*"[^"]*(?:display:\s*none|font-size:\s*0)',
        ],
        remediation="Strip invisible unicode from all tool metadata; validate descriptions",
        discovered_date="2025-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-54136"],
    ),
    CVEEntry(
        id="CVE-2026-23744",
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        cwe_id="CWE-94",
        affected_component="MCPJam Inspector",
        vendor="MCPJam",
        description="Remote code execution in MCPJam MCP Inspector tool",
        attack_vector="Crafted MCP server response triggers code execution in the Inspector's rendering",
        detection_patterns=[
            r'mcpjam|mcp-inspector',
            r'"tool_result".*(?:<script|javascript:|onerror)',
        ],
        remediation="Sanitize all MCP responses before rendering in Inspector UI",
        discovered_date="2026-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-23744"],
    ),
    CVEEntry(
        id="CVE-2026-13341",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-74",
        affected_component="Kong Konnect MCP integration",
        vendor="Kong",
        description="Injection in Kong Konnect MCP integration allows API gateway manipulation",
        attack_vector="Crafted tool parameters injected into Kong admin API calls",
        detection_patterns=[
            r'(?:kong|konnect).*mcp',
            r'"tool".*(?:kong|gateway|route|service|upstream)',
        ],
        remediation="Parameterize all Kong admin API calls; validate tool input schemas",
        discovered_date="2026-02",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-13341"],
    ),
]


# ---------------------------------------------------------------------------
# 2. PAYMENT BYPASS CVEs
# ---------------------------------------------------------------------------

PAYMENT_BYPASS_CVES: list[CVEEntry] = [
    CVEEntry(
        id="CVE-2026-41432",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        cwe_id="CWE-345",
        affected_component="Stripe webhook signing",
        vendor="Multiple (1,542 apps)",
        description="Empty Stripe webhook signing secret is the DEFAULT; attacker forges checkout.session.completed with HMAC over empty key",
        attack_vector="Compute HMAC-SHA256 with empty string as key; send forged webhook with valid signature; 1,542 apps accept it",
        detection_patterns=[
            r'(?:whsec_|webhook_secret|STRIPE_WEBHOOK_SECRET)\s*[=:]\s*["\']?\s*["\']',
            r'stripe.*webhook.*(?:!verify|!signature|no.*sign)',
            r'checkout\.session\.completed.*(?:payment_status.*unpaid|amount_total.*0)',
            r'(?:Stripe-Signature|stripe_signature)\s*:\s*(?:t=\d+,v1=[a-f0-9]+)',
            r'constructEvent.*(?:""|\'\').*(?:secret|signing)',
        ],
        remediation="Always set a non-empty webhook signing secret; verify signatures with Stripe SDK constructEvent",
        discovered_date="2026-06",
        references=["https://github.com/advisories/GHSA-xff3-5c9p-2mr4"],
    ),
    CVEEntry(
        id="CVE-2026-73314",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        cwe_id="CWE-345",
        affected_component="XenForo PayPal IPN",
        vendor="XenForo",
        description="PayPal IPN verification bypass in XenForo grants premium membership without payment",
        attack_vector="Crafted IPN notification with valid-looking parameters accepted without PayPal verification callback",
        detection_patterns=[
            r'(?:paypal|ipn).*(?:notify|callback).*(?:!verify|!validated)',
            r'payment_status\s*[=:]\s*["\']?Completed.*(?:!paypal\.com)',
            r'ipn.*(?:VERIFIED|INVALID).*(?:skip|bypass)',
        ],
        remediation="Always verify IPN by POSTing back to PayPal; check txn_id uniqueness",
        discovered_date="2026-08",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-73314"],
    ),
    CVEEntry(
        id="CVE-2026-11964",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N",
        cwe_id="CWE-345",
        affected_component="WordPress membership plugin",
        vendor="WordPress Plugin",
        description="WordPress membership plugin accepts forged PayPal payment notifications granting unlimited access",
        attack_vector="POST crafted IPN to membership webhook endpoint; plugin does not verify with PayPal",
        detection_patterns=[
            r'wp-content.*(?:membership|premium|paypal).*(?:ipn|webhook|callback)',
            r'(?:wp_ajax|admin-ajax).*(?:paypal|payment).*(?:complete|success)',
            r'update_user_meta.*(?:membership|premium|access_level)',
        ],
        remediation="Verify all payment notifications server-to-server with the payment provider",
        discovered_date="2026-02",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-11964"],
    ),
    CVEEntry(
        id="CVE-2026-33731",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        cwe_id="CWE-345",
        affected_component="AVideo Authorize.Net integration",
        vendor="AVideo",
        description="AVideo accepts Authorize.Net payment confirmation without server-side verification",
        attack_vector="Client-side payment confirmation POST to AVideo grants video access without actual payment",
        detection_patterns=[
            r'(?:authorize\.net|authorizenet).*(?:!verify|!server)',
            r'(?:x_response_code|x_trans_id).*(?:client|direct)',
        ],
        remediation="Verify transactions server-to-server with Authorize.Net API",
        discovered_date="2026-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-33731"],
    ),
    CVEEntry(
        id="CVE-2026-71537",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
        cwe_id="CWE-362",
        affected_component="Paymenter billing",
        vendor="Paymenter",
        description="Credit-refund race condition in Paymenter allows infinite credit generation",
        attack_vector="Race concurrent refund and credit requests; both succeed, doubling credit balance each iteration",
        detection_patterns=[
            r'(?:refund|credit).*(?:race|concurrent|parallel)',
            r'(?:balance|credits?).*(?:negative|overflow|doubled)',
            r'(?:refund.*credit|credit.*refund).*(?:simultaneous|concurrent)',
        ],
        remediation="Serialize credit/refund operations with database-level locking",
        discovered_date="2026-09",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-71537"],
    ),
    CVEEntry(
        id="CVE-2026-89411",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        cwe_id="CWE-345",
        affected_component="Paymattic payment processing",
        vendor="Paymattic",
        description="Payment intent ID reuse allows replaying a single payment to gain multiple entitlements",
        attack_vector="Same payment_intent ID accepted on multiple subscription activations",
        detection_patterns=[
            r'payment_intent.*(?:reuse|replay|duplicate)',
            r'pi_[A-Za-z0-9]+.*(?:already|used|previous)',
            r'(?:activate|grant).*(?:pi_|payment_intent).*(?:!unique|!once)',
        ],
        remediation="Track and reject already-consumed payment_intent IDs; enforce idempotency keys",
        discovered_date="2026-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-89411"],
    ),
    CVEEntry(
        id="CVE-2026-131170",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        cwe_id="CWE-345",
        affected_component="Payment status session handling",
        vendor="Multiple",
        description="Payment status reuse across sessions allows one payment to unlock multiple accounts",
        attack_vector="Payment confirmation stored in shared session/cookie; replayed across different user contexts",
        detection_patterns=[
            r'(?:session|cookie).*(?:payment_status|paid|confirmed).*(?:reuse|shared|cross)',
            r'(?:payment_confirmed|is_paid)\s*[=:]\s*true.*(?:session|cookie)',
        ],
        remediation="Bind payment confirmation to specific user and session; use server-side verification",
        discovered_date="2026-11",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-131170"],
    ),
]


# ---------------------------------------------------------------------------
# 3. ENTERPRISE PLATFORM CVEs
# ---------------------------------------------------------------------------

ENTERPRISE_PLATFORM_CVES: list[CVEEntry] = [
    CVEEntry(
        id="CVE-2026-21589",
        cvss_score=9.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        cwe_id="CWE-22",
        affected_component="Atlassian Confluence",
        vendor="Atlassian",
        description="Arbitrary file read in Atlassian Confluence allows reading any file on the server",
        attack_vector="Path traversal in Confluence REST API endpoint; read /etc/passwd, application configs, database credentials",
        detection_patterns=[
            r'(?:confluence|atlassian).*(?:rest|api).*\.\.\/',
            r'/wiki/rest/.*(?:\.\.|%2e%2e)',
            r'(?:confluence).*(?:/etc/passwd|/opt/atlassian|confluence\.cfg\.xml)',
        ],
        remediation="Upgrade Confluence; patch file read endpoints to canonicalize paths",
        discovered_date="2026-03",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-21589"],
    ),
    CVEEntry(
        id="CVE-2024-10327",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        cwe_id="CWE-287",
        affected_component="Okta MFA",
        vendor="Okta",
        description="MFA bypass via API allows authentication without completing MFA challenge",
        attack_vector="Direct API authentication endpoint bypasses MFA enforcement policy",
        detection_patterns=[
            r'(?:okta|oktapreview)\.com.*/api/v1/authn',
            r'(?:sessionToken|stateToken).*(?:!mfa|!factor)',
            r'authn.*status.*(?:SUCCESS|MFA_REQUIRED).*(?:bypass|skip)',
        ],
        remediation="Enforce MFA at the authentication layer for all authentication methods including API",
        discovered_date="2024-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-10327"],
    ),
    CVEEntry(
        id="CVE-2025-3648",
        cvss_score=8.2,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-863",
        affected_component="ServiceNow ACL",
        vendor="ServiceNow",
        description="ACL bypass in ServiceNow allows unauthorized data access",
        attack_vector="Crafted GlideRecord query bypasses table-level ACL restrictions",
        detection_patterns=[
            r'(?:servicenow|service-now).*(?:api|rest).*(?:table|sys_)',
            r'sysparm_query.*(?:sys_id|sys_class_name).*(?:javascript|script)',
            r'(?:GlideRecord|GlideAggregate).*(?:!acl|bypass)',
        ],
        remediation="Review and tighten all ACL rules; enforce query restrictions at the platform level",
        discovered_date="2025-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-3648"],
    ),
    CVEEntry(
        id="CVE-2026-22817",
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-327",
        affected_component="JWT implementation",
        vendor="Multiple",
        description="JWT RS256 to HS256 algorithm confusion allows token forgery with public key",
        attack_vector="Change JWT alg header from RS256 to HS256; sign with the server's public RSA key (which is public); server validates using HMAC with the public key",
        detection_patterns=[
            r'"alg"\s*:\s*"(?:HS256|HS384|HS512|none|None|NONE|nOnE)"',
            r'(?:RS256|RS384|RS512).*(?:HS256|HS384|HS512).*(?:confused|downgrade)',
            r'"alg"\s*:\s*"none"',
            r'"kid"\s*:\s*".*(?:\.\.|/|;|\\\\|\'|")',
            r'"jku"\s*:\s*"https?://(?!(?:login|auth|sso)\.[a-z]+\.com)',
        ],
        remediation="Explicitly specify allowed algorithms on verification; never accept alg from token",
        discovered_date="2026-03",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-22817"],
    ),
    CVEEntry(
        id="CVE-2026-27804",
        cvss_score=9.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        cwe_id="CWE-287",
        affected_component="Parse Server",
        vendor="Parse Platform",
        description="JWT authentication bypass in Parse Server allows unauthenticated admin access",
        attack_vector="Crafted JWT with alg:none or algorithm confusion bypasses Parse Server auth entirely",
        detection_patterns=[
            r'(?:parse|parseplatform).*(?:jwt|token|auth)',
            r'X-Parse-(?:Session-Token|Application-Id|REST-API-Key)',
            r'parse.*(?:alg.*none|RS256.*HS256)',
        ],
        remediation="Upgrade Parse Server; pin JWT algorithm; validate issuer and audience claims",
        discovered_date="2026-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-27804"],
    ),
]


# ---------------------------------------------------------------------------
# 4. THREAT INTELLIGENCE METRICS (Nov 2026)
# ---------------------------------------------------------------------------

THREAT_INTELLIGENCE: dict[str, Any] = {
    # LLMjacking
    "llmjacking_daily_cost": 100_000,
    "llmjacking_max_incident": 1_000_000,
    "llmjacking_key_price_low": 15,
    "llmjacking_key_price_high": 30,
    "llmjacking_resale_discount_pct": 97,
    "llmjacking_credential_theft_increase_pct": 376,
    # Distillation theft
    "distillation_exchanges_total": 190_000_000,
    "distillation_labs_involved": 7,
    "distillation_alibaba_daily": 3_000_000,
    "distillation_alibaba_accounts": 3_500,
    "distillation_moonshot_total": 23_000_000,
    "distillation_moonshot_accounts": 5_380,
    "distillation_deepseek_14day": 12_100_000,
    # MCP ecosystem
    "mcp_servers_poisoned_pct": 5.5,
    "mcp_cves_per_month": 68,
    "mcptox_success_rate": 36.5,
    "sharelock_success_rate": 90.0,
    "mcp_total_cves_2025_2026": 40,
    # Credential exposure
    "unsigned_webhook_apps": 1_542,
    "exposed_settings_files": 104_185,
    "npm_packages_with_claude_config": 428,
    "npm_packages_with_real_creds": 33,
    "repos_with_credentials_json": 371,
    # Bot detection
    "turnstile_catch_rate": 42.1,
    "cloudflare_bot_mgmt_catch_rate": 9.1,
    # Frontier AI offensive capability
    "exploitgym_mythos_exploits": 157,
    "exploitgym_gpt55_exploits": 120,
    "chrome_cves_by_claude": 62,
    "cybench_score_latest": 93.0,
    "cybench_score_15months_ago": 12.5,
    "xbow_bounty_max": 250_000,
    # Financial impact
    "metr_incident_cost": 600_000,
    "railway_incident_cost": 740_000,
    "jet_night_calls": 500_000,
    "gemini_48h_cost": 82_000,
}


# ---------------------------------------------------------------------------
# 5. COMBINED DATABASE + HELPERS
# ---------------------------------------------------------------------------

_ALL_CVES: list[CVEEntry] = CLAUDE_MCP_CVES + PAYMENT_BYPASS_CVES + ENTERPRISE_PLATFORM_CVES

_CVE_BY_ID: dict[str, CVEEntry] = {c.id: c for c in _ALL_CVES}

_CATEGORY_MAP: dict[str, list[CVEEntry]] = {
    "claude_mcp": CLAUDE_MCP_CVES,
    "payment_bypass": PAYMENT_BYPASS_CVES,
    "enterprise_platform": ENTERPRISE_PLATFORM_CVES,
}


def get_cves_by_category(category: str) -> list[CVEEntry]:
    return list(_CATEGORY_MAP.get(category, []))


def get_cves_by_vendor(vendor: str) -> list[CVEEntry]:
    v = vendor.lower()
    return [c for c in _ALL_CVES if v in c.vendor.lower()]


def get_cves_above_cvss(threshold: float) -> list[CVEEntry]:
    return sorted(
        [c for c in _ALL_CVES if c.cvss_score >= threshold],
        key=lambda c: c.cvss_score,
        reverse=True,
    )


def get_detection_patterns_for_cve(cve_id: str) -> list[str]:
    entry = _CVE_BY_ID.get(cve_id)
    return list(entry.detection_patterns) if entry else []


def get_all_cves() -> list[CVEEntry]:
    return list(_ALL_CVES)


def get_cve(cve_id: str) -> CVEEntry | None:
    return _CVE_BY_ID.get(cve_id)


def get_threat_metric(key: str) -> Any:
    return THREAT_INTELLIGENCE.get(key)


def get_critical_cves() -> list[CVEEntry]:
    return get_cves_above_cvss(9.0)


def get_high_cves() -> list[CVEEntry]:
    return [c for c in _ALL_CVES if 7.0 <= c.cvss_score < 9.0]


def summarize_database() -> dict[str, Any]:
    return {
        "total_cves": len(_ALL_CVES),
        "by_category": {k: len(v) for k, v in _CATEGORY_MAP.items()},
        "critical_count": len(get_critical_cves()),
        "high_count": len(get_high_cves()),
        "avg_cvss": round(sum(c.cvss_score for c in _ALL_CVES) / len(_ALL_CVES), 2),
        "vendors": sorted(set(c.vendor for c in _ALL_CVES)),
        "cwes": sorted(set(c.cwe_id for c in _ALL_CVES)),
    }
