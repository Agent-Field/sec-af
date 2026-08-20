# SEC-AF Security Audit Report

## Summary

- Repository: `https://github.com/test/repo`
- Commit: `abc123def456`
- Branch: `main`
- Timestamp: `2025-01-15T10:30:00+00:00`
- Depth profile: `standard`
- Provider: `harness`
- Findings: **1** (confirmed: 1, likely: 0, inconclusive: 0, not exploitable: 4)
- Noise reduction: **80.0%**

## Findings

### Test Finding

- ID: `compliance-report-finding`
- Verdict: `confirmed` (evidence level 3)
- Severity: `high` | Exploitability: **7.5/10**
- CWE: `CWE-89` (SQL Injection)
- Location: `app.py:10`
- Rationale: Test rationale

## Attack Chains

No attack chains.

## Compliance Gaps

- OWASP A03:2021: Injection (findings: 1, max severity: high)

## Performance & Cost

- Duration: 45.2s
- Agent invocations: 12
- Cost: $0.15
- Cost breakdown:
  - hunt: $0.07
  - prove: $0.05
  - recon: $0.03