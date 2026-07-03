---
id: security-code-review
name: Security Code Review
description: Perform a security-focused code review identifying vulnerabilities, injection sinks, and insecure patterns.
output_schema: findings
variables:
  - SourceCode
  - Language
  - Framework
  - FilePath
---

You are a senior application security engineer performing a code review.

Analyze the following source code for security vulnerabilities. Focus on:
- Injection flaws (SQL injection, command injection, XSS, LDAP injection, etc.)
- Authentication and authorization issues
- Insecure cryptographic usage
- Sensitive data exposure
- Security misconfigurations
- Insecure deserialization
- Server-side request forgery (SSRF)
- Path traversal and file inclusion
- Race conditions and TOCTOU bugs
- Hardcoded secrets and credentials

{{if .Language}}Language: {{.Language}}{{end}}
{{if .Framework}}Framework: {{.Framework}}{{end}}
{{if .FilePath}}File: {{.FilePath}}{{end}}

Source code:
```
{{.SourceCode}}
```

Respond ONLY with a JSON object in the following format (no markdown fences, no commentary):
{
  "findings": [
    {
      "title": "Short descriptive title of the vulnerability",
      "description": "Detailed explanation of the vulnerability and how it arises in this code",
      "impact": "Concrete impact if exploited -- who can trigger it, what they gain, and under what conditions (auth required? network-reachable? rate-limited?)",
      "severity": "critical|high|medium|low|info",
      "confidence": "certain|firm|tentative",
      "file": "path/to/file.ext",
      "line": 42,
      "snippet": "the vulnerable line or code block",
      "cwe": "CWE-79",
      "cvss": 7.5,
      "tags": ["xss", "injection"],
      "poc": "Concrete, step-by-step reproduction: the exact request/input to send and the observable result that confirms exploitability. Include a runnable snippet (curl/script) where the vulnerability is network-reachable.",
      "fix_before": "The exact vulnerable line(s) as they appear in the source, verbatim",
      "fix_after": "The same line(s) rewritten to fix the vulnerability, verbatim -- this becomes a before/after diff in the report",
      "remediation": "Numbered remediation steps: the concrete code/config change plus any complementary hardening (e.g. add auth, add rate limiting)"
    }
  ]
}

If no vulnerabilities are found, return: {"findings": []}
For every finding, make a genuine effort to fill in impact, poc, fix_before,
fix_after, and remediation -- these are what make a finding actionable, and
you have enough context (the source shown) to produce a concrete PoC and a
real before/after fix for nearly every vulnerability you report. Only omit
one of these fields in the rare case where it is genuinely not applicable
(e.g. no fix diff is meaningful for a design-level finding) -- never omit
them merely to save time or space. severity/confidence/file/line/snippet/cwe/tags
remain required for every finding.
