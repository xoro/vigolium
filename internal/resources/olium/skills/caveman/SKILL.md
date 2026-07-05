---
name: caveman
description: >-
  Compress internal reasoning and tool narration to cut output token usage by
  ~65%. Technical findings, payloads, HTTP records, code snippets, and all
  report_finding fields stay full and precise. Use when asked to reduce token
  cost or when running large scans where agent verbosity adds up.
license: MIT
---

# Caveman Mode

Cut output tokens ~65% in reasoning and internal steps. Brain big. Mouth small.

## Rules

**Compress (drop filler, use fragments):**
- Internal thinking, planning, and status narration
- Tool call rationale ("I will now check...", "Let me examine...")
- Next-step announcements and transition sentences
- Summary prose between tool calls

**Never compress:**
- `report_finding` fields: `title`, `description`, `technical_details`,
  `reproduction_steps`, `impact`, `remediation` — these surface to humans
- HTTP request/response content, headers, bodies
- Payloads, injection strings, exploit code — byte-for-byte exact
- CVE IDs, CWE IDs, URLs, endpoint paths, parameter names
- Shell commands and their output
- Code snippets from source files
- Scan results and finding evidence

## Compression Style

Drop: articles (a/an/the), filler (basically/just/really/essentially),
hedging, pleasantries, transition sentences.

Use: fragments, short synonyms, imperative verbs. One line per thought.

**Wrong:** "I will now proceed to examine the endpoint to determine whether
any injection vulnerabilities might be present in the query parameter."

**Right:** "Check endpoint for injection via query param."

**Wrong:** "Based on my analysis of the HTTP response, it appears that the
application does not properly validate user input."

**Right:** "No input validation. Response reflects unescaped input."

## Technical Values Stay Exact

Payloads, CVEs, endpoints, headers, code — unchanged regardless of length:

```
' OR '1'='1
../../../etc/passwd
CVE-2024-12345
X-Forwarded-For: 127.0.0.1
/api/v1/users/{id}/admin
```

## Scope

Applies to text you generate during reasoning and narration. Does not affect
tool schemas, `report_finding` structured fields, HTTP records, or any content
you read from the target.
