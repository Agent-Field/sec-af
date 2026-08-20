# SEC-AF Security Audit Report

## Summary

- Repository: `Agent-Field/sec-af`
- Commit: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Branch: `issue-23-tests`
- Timestamp: `2026-03-04T10:30:00+00:00`
- Depth profile: `standard`
- Provider: `opencode`
- Findings: **3** (confirmed: 1, likely: 1, inconclusive: 0, not exploitable: 1)
- Noise reduction: **66.7%**

## Findings

### SQL Injection

- ID: `finding-confirmed`
- Verdict: `confirmed` (evidence level 6)
- Severity: `critical` | Exploitability: **10.0/10**
- CWE: `CWE-89` (SQL Injection)
- Location: `src/users.py:42`
- Chain: `chain-1` step 1
- Data flow trace:
  - `src/routes.py:15` - Input source
  - `src/users.py:42` - SQL sink
- Rationale: Source-to-sink path is confirmed and exploitable.

### Missing Authentication

- ID: `finding-likely`
- Verdict: `likely` (evidence level 2)
- Severity: `high` | Exploitability: **4.8/10**
- CWE: `CWE-306` (Missing Authentication for Critical Function)
- Location: `src/api/admin.py:11`
- Rationale: Guard checks appear absent on route.

### Potential XSS

- ID: `finding-noise`
- Verdict: `not_exploitable` (evidence level 1)
- Severity: `low` | Exploitability: **0.6/10**
- CWE: `CWE-79` (Cross-site Scripting)
- Location: `src/views.py:88`
- Rationale: Sink auto-escapes output.

## Attack Chains

### Input to DB read

- Chain ID: `chain-1`
- Combined severity: `critical`
- Combined impact: Unauthorized DB disclosure
- Findings: `finding-confirmed`, `finding-likely`
- MITRE ATT&CK:
  - T1190 (Initial Access): Exploit Public-Facing Application

## Compliance Gaps

- PCI-DSS Req 6.2.4: Prevent injection (findings: 1, max severity: critical)

## Performance & Cost

- Duration: 182.4s
- Agent invocations: 24
- Cost: $3.21
- Cost breakdown:
  - hunt: $1.20
  - prove: $1.51
  - recon: $0.50