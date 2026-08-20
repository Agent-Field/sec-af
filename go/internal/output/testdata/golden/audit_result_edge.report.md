# SEC-AF Security Audit Report

## Summary

- Repository: `Agent-Field/sec-af—naïve`
- Commit: `abc123`
- Branch: n/a
- Timestamp: `2026-03-04T10:30:00.123456+00:00`
- Depth profile: `thorough`
- Provider: `aforge`
- Findings: **4** (confirmed: 1, likely: 1, inconclusive: 1, not exploitable: 1)
- Noise reduction: **0.0%**

## Findings

### Naïve "quote" & <tag> handling

- ID: `dup-a`
- Verdict: `likely` (evidence level 3)
- Severity: `medium` | Exploitability: **4.5/10**
- CWE: `CWE-89` (SQL Injection)
- Location: `src/naïve.py:3`
- Chain: `chain-x` step ?

### Second finding on the same rule

- ID: `dup-b`
- Verdict: `confirmed` (evidence level 6)
- Severity: `critical` | Exploitability: **9.2/10**
- CWE: `CWE-89` (SQL Injection)
- Location: `src/dup.py:7`
- Data flow trace:
  - `src/§.py:1` - source → sink
- Rationale: Confirmed by trace.

### Rule id with an empty last segment

- ID: `rule-fallback`
- Verdict: `inconclusive` (evidence level 1)
- Severity: `info` | Exploitability: **0.0/10**
- CWE: `cwe-79` (Cross-site Scripting)
- Location: `src/views.py:1`
- Rationale: Unclear.

### Filtered out of SARIF

- ID: `dropped`
- Verdict: `not_exploitable` (evidence level 1)
- Severity: `low` | Exploitability: **1.0/10**
- CWE: `CWE-798` (Hard-coded Credentials)
- Location: `src/config.py:5`
- Rationale: False positive.

## Attack Chains

### Chain naming a missing finding

- Chain ID: `chain-x`
- Combined severity: `high`
- Combined impact: Impact <script> & co.
- Findings: `dup-a`, `not-in-result`

## Compliance Gaps

- OWASP A03:2021: Injection (findings: 7, max severity: info)
- OWASP A01:2021: Broken Access Control (findings: 1, max severity: unknown-severity)

## Performance & Cost

- Duration: 0.1s
- Agent invocations: 3
- Cost: $1.00
- Cost breakdown:
  - hunt: $1.00
  - prove: $0.00