# SEC-AF Refactoring Plan: Composite Intelligence Alignment

## Guiding Principle

> "The whole point is we have intelligence that can autonomously think at various levels.
> If things can be done programmatically, that is not something we replicate with AI.
> We use AI where intelligence creates value that code alone cannot provide."

**Two axes of change:**
1. **Schema Decomposition** — Break complex single-AI-call schemas into focused sub-agent calls (2-4 fields each)
2. **Intelligence Activation** — Replace hardcoded domain knowledge with AI reasoning where judgment adds value

**Benchmark:** DVGA (Damn Vulnerable GraphQL Application) — 19-item roadmap across 4 tiers, integrated below.

---

## Milestones & Issue Tracker

| Milestone | Issues | Focus |
|---|---|---|
| **v1.1** — Pipeline Fixes + Quick Intelligence | [#47](#47)–[#53](#53) | Fix dropped findings, activate dead code, speed |
| **v1.2** — New Hunters + Schema Decomposition | [#54](#54)–[#64](#64) | XSS/DoS/SSRF/business logic hunters, Composite Intelligence refactoring |
| **v1.3** — Architecture Improvements | [#65](#65)–[#69](#69) | Multi-language, framework-aware, PR-mode, DAST |
| **v2.0** — Enterprise & Competitive Moat | [#70](#70)–[#74](#74) | Cross-service chains, remediation code, monitoring, policies, compliance PDF |

All issues: https://github.com/Agent-Field/sec-af/issues

---

## v1.1 — Pipeline Fixes + Quick Intelligence

These are immediate fixes that improve detection quality without architectural changes. All are independent and can be built in parallel.

### Fix: Prove phase dropping real findings — [#47](https://github.com/Agent-Field/sec-af/issues/47)

**Problem:** The PROVE phase drops valid findings when the verifier returns `verdict=unverified` due to insufficient context or schema retry failures. DVGA benchmark shows we find vulns in HUNT but lose them in PROVE.

**Fix:** Track drop reasons, add fallback logic (demote to `low_confidence` instead of dropping), surface drop metrics.

**Files:** `agents/prove/verifier.py`, `orchestrator.py`
**Effort:** Medium | **Impact:** High — directly recovers lost findings

---

### Fix: Surface recon detections as standalone findings — [#48](https://github.com/Agent-Field/sec-af/issues/48)

**Problem:** RECON phase detects security-relevant items (hardcoded secrets, dangerous configs, weak TLS) but only passes them as context to HUNT. If no hunter picks them up, they're lost.

**Fix:** Emit `RawFinding` entries directly from recon detections with appropriate severity.

**Files:** `agents/recon/__init__.py`, `agents/recon/config_scanner.py`, `schemas/hunt.py`
**Effort:** Medium | **Impact:** High — new finding source

---

### Fix: Schema retry prompt missing schema context — [#49](https://github.com/Agent-Field/sec-af/issues/49)

**Problem:** When AgentField retries a failed schema parse, the retry prompt doesn't include the schema definition, leading to repeated failures.

**Fix:** Include schema JSON in retry prompts.

**Files:** `harness.py`
**Effort:** Low | **Impact:** High — reduces schema parse failures across all phases

---

### Speed optimization — [#50](https://github.com/Agent-Field/sec-af/issues/50)

**Problem:** Full scan takes 69 minutes. Budget allocation and sequential phases create bottlenecks.

**Fix:** Parallel hunter execution, budget rebalancing, early termination for low-value strategies.

**Files:** `orchestrator.py`, `config.py`
**Effort:** Medium | **Impact:** High — prerequisite for CI/CD integration (#67)
**Dependency:** None, but enables #67

---

### Activate strategy selection AI gate (dead code) — [#51](https://github.com/Agent-Field/sec-af/issues/51)

**Problem:** `StrategySelection` schema and `AIGateWrapper.select_strategy()` already exist in `harness.py` but are NEVER CALLED. The orchestrator uses hardcoded if/else:

```python
# orchestrator.py / phases.py — current hardcoded logic
strategies = [INJECTION, AUTH, DATA_EXPOSURE, CONFIG_SECRETS]
if recon.security_context.crypto_usage:
    strategies.append(CRYPTO)
if recon.dependencies.direct_count > 0:
    strategies.append(SUPPLY_CHAIN)
```

**Why AI:** "Given this Python/Django app with JWT auth, PostgreSQL, and 200 API endpoints — which security strategies should we prioritize?" is a JUDGMENT call. The AI can weigh recon context holistically, not just check boolean flags.

**Change:**
- Wire existing `select_strategy()` into the orchestrator flow
- Pass hardcoded defaults as `default_candidates` (AI confirms/adjusts)
- Keep hardcoded defaults as fallback if AI gate fails

**Implementation in `phases.py`:**
```python
async def hunt_phase(repo_path, recon_context, depth):
    recon = ReconResult(**recon_context)
    
    # Hardcoded defaults as candidates
    default_strategies = _default_strategies(recon, depth)
    
    # AI gate refines strategy selection
    try:
        ai_gate = AIGateWrapper(router)
        selection = await ai_gate.select_strategy(
            recon_summary=_recon_summary_string(recon),  # String, not JSON!
            depth=depth,
            default_candidates=[s.value for s in default_strategies],
        )
        strategies = [HuntStrategy(s) for s in selection.strategies]
    except Exception:
        strategies = default_strategies  # Fallback to hardcoded
    
    # ... rest of hunt phase
```

**Files:** `phases.py`, `orchestrator.py`
**Effort:** Low (code already exists!) | **Impact:** Medium — adaptive strategy selection

---

### Hybrid compliance mapping with AI fallback — [#52](https://github.com/Agent-Field/sec-af/issues/52)

**Problem:** `compliance/mapping.py` hardcodes ~30 CWE→compliance mappings. Any CWE not in the map (e.g., CWE-502 Deserialization, CWE-611 XXE) returns ZERO compliance mappings. There are 900+ CWEs — we cover 3%.

**Why AI:** CWE→compliance mapping is expert security knowledge. LLMs have excellent knowledge of PCI-DSS, SOC2, OWASP, HIPAA, ISO27001 controls. This is exactly where intelligence adds value code cannot.

**Change:**
- Keep `COMPLIANCE_MAP` as fast-path cache (zero-latency for known CWEs)
- Add `.ai()` fallback for CWEs not in the map
- Cache AI results to disk/memory to avoid re-computation across runs

**New schema** (`schemas/gates.py`):
```python
class ComplianceSuggestion(BaseModel):
    framework: str       # "PCI-DSS"
    control_id: str      # "Req 6.2.4"
    control_name: str    # "Prevent injection attacks"

class ComplianceGate(BaseModel):
    mappings: list[ComplianceSuggestion]
    confidence: str      # "high" | "medium" | "low"
```

**Files:** `compliance/mapping.py`, `schemas/gates.py`, `orchestrator.py`
**Effort:** Low | **Impact:** High — every previously-unmapped CWE now gets compliance data
**Dependency:** None, but enables #74

---

### AI-primary attack chain detection — [#53](https://github.com/Agent-Field/sec-af/issues/53)

**Problem:** `dedup.py` has `_CHAIN_PATTERNS` with only 4 hardcoded CWE pairs. The AI harness often returns no chains, so the 4 hardcoded pairs are the only chains found.

**Why AI:** Attack chain reasoning requires understanding HOW vulnerabilities compose semantically — "SQL injection at endpoint A can extract the admin JWT secret found hardcoded at location B, enabling auth bypass at endpoint C." This is intelligence, not lookup.

**Change:**
- Pass hardcoded chain patterns as SEED CANDIDATES in the dedup prompt
- Make AI the primary chain detector with richer context
- Keep hardcoded patterns only as emergency fallback

**Files:** `dedup.py`
**Effort:** Low | **Impact:** Medium — dramatically more chains discovered

---

## v1.2 — New Hunters + Schema Decomposition

### New Hunters (DVGA Tier 2)

These fill critical detection gaps. All follow the existing hunter pattern and are independent.

| Issue | Hunter | CWEs | Priority |
|---|---|---|---|
| [#54](https://github.com/Agent-Field/sec-af/issues/54) | XSS / Client-side injection | CWE-79, 80, 87, 116 | High |
| [#55](https://github.com/Agent-Field/sec-af/issues/55) | DoS / Resource exhaustion | CWE-400, 770, 1333, 835 | Medium |
| [#56](https://github.com/Agent-Field/sec-af/issues/56) | SSRF (dedicated) | CWE-918 | Medium |
| [#57](https://github.com/Agent-Field/sec-af/issues/57) | Enhanced cryptography / secrets | CWE-326, 327, 328, 330, 916, 259, 321, 798 | Medium |
| [#58](https://github.com/Agent-Field/sec-af/issues/58) | Business logic vulnerabilities | CWE-840, 841, 362, 367, 639 | High |

**Pattern:** Each creates `agents/hunt/<name>.py` + `prompts/hunt/<name>.txt` + updates `HuntStrategy` enum.

**Composite Intelligence note:** Business logic (#58) is the purest expression of "intelligence where it adds value" — no static rules can detect business logic flaws. The AI must reason about intended behavior vs actual behavior.

---

### Composite Intelligence Refactoring (Schema Decomposition)

#### Context passing as focused strings — [#59](https://github.com/Agent-Field/sec-af/issues/59)

**Problem:** RECON results are dumped as full JSON into HUNT/PROVE prompts via `recon.model_dump_json()` — 5-10KB of raw JSON that agents must parse.

**Composite Intelligence Principle:** "Pass as context to another LLM? → USE STRING" + "Each agent must receive exactly the right context — not too much, not too little."

**Change:** New `src/sec_af/context.py` module with per-strategy context builders:

```python
def recon_context_for_injection(recon: ReconResult) -> str:
    """Focused context for injection hunters — only relevant slices."""
    entry_points = "\n".join(
        f"  - {ep.method or 'ANY'} {ep.route or ep.identifier} ({ep.file_path}:{ep.line})"
        for ep in recon.architecture.entry_points[:15]
    )
    sinks = "\n".join(
        f"  - {s.sink_type} at {s.file_path}:{s.line}"
        for s in recon.data_flows.sinks[:10]
    )
    return f"""Application type: {recon.architecture.app_type}
Languages: {', '.join(recon.languages)}
Frameworks: {', '.join(recon.frameworks)}
Auth model: {recon.security_context.auth_model}

Entry points ({len(recon.architecture.entry_points)} total):
{entry_points}

Known sinks ({len(recon.data_flows.sinks)} total):
{sinks}"""
```

**Files:** New `context.py`, all `agents/hunt/*.py`, all `prompts/hunt/*.txt`
**Effort:** Medium | **Impact:** Medium — focused context = better agent performance
**Dependency:** None, but is prerequisite for #61, #62, #63, #65

---

#### Reachability assessment .ai() gate — [#60](https://github.com/Agent-Field/sec-af/issues/60)

**Problem:** Scoring formula uses `REACHABILITY_MULTIPLIERS` based on tags like `"externally_reachable"`, but these tags are inconsistently set — often missing, defaulting to `requires_auth` (0.5).

**Schema (flat, 3 fields):** `ReachabilityGate(reachability: str, rationale: str, confidence: str)`

**Files:** `orchestrator.py`, `schemas/gates.py`
**Effort:** Low | **Impact:** Medium — more accurate exploitability scores
**Dependency:** None

---

#### Dynamic CWE expansion — [#61](https://github.com/Agent-Field/sec-af/issues/61)

**Problem:** Each hunter hardcodes a fixed CWE list. Novel CWE classes are missed.

**Schema (flat, 2 fields):** `CWEExpansion(additional_cwes: list[str], rationale: str)`

**Composite Intelligence Principle:** Guided Autonomy — AI expands within bounds (suggest additions, not replacements).

**Files:** `phases.py`, `schemas/gates.py`, all hunter agents
**Effort:** Medium | **Impact:** Medium
**Dependency:** Depends on #59 (context strings)

---

#### Decompose PROVE into sub-agent chain — [#62](https://github.com/Agent-Field/sec-af/issues/62) ⭐ HIGHEST PRIORITY

**Problem:** Single `.harness()` call produces `VerifiedFinding` — 27 fields, 4 nesting levels. One agent does 5 cognitive tasks simultaneously: trace data flow, analyze sanitization, construct exploit, determine verdict, build reproduction steps.

**Composite Intelligence Principle:** "No complex problem should ever be solved by a single agent in a single step. Each LLM call should handle 2-4 simple attributes."

**New sub-agents:**

| Step | Agent | Schema | Fields | Parallel? |
|---|---|---|---|---|
| 1 | DataFlowTracer | DataFlowTrace | `source, sink, steps, sink_reached` — 4 fields | Yes (with 2) |
| 2 | SanitizationAnalyzer | SanitizationResult | `found, type, sufficient, bypass_method` — 4 fields | Yes (with 1) |
| 3 | ExploitHypothesizer | ExploitHypothesis | `hypothesis, payload, expected_outcome` — 3 fields | After 1+2 |
| 4 | VerdictAgent (.ai()) | VerdictDecision | `verdict, evidence_level, rationale, confidence` — 4 fields | After 1+2+3 |
| 5 | Assembler (code) | VerifiedFinding | Pure code — no AI | — |

**Flow:**
```
Finding from HUNT
    │
    ├──► DataFlowTracer (.harness)  ─┐
    │                                 ├──► ExploitHypothesizer (.harness)
    └──► SanitizationAnalyzer (.harness) ─┘         │
                                                     ▼
                                            VerdictAgent (.ai)
                                                     │
                                                     ▼
                                           assembler.py (code)
                                                     │
                                                     ▼
                                            VerifiedFinding
```

**New files:** `agents/prove/{tracer,sanitization,exploit,verdict,assembler}.py`, `prompts/prove/{tracer,sanitization,exploit,verdict}.txt`
**Effort:** High | **Impact:** Highest — each agent focuses on ONE cognitive task
**Dependency:** Depends on #59 (context strings)

---

#### Decompose HUNT finding production — [#63](https://github.com/Agent-Field/sec-af/issues/63)

**Problem:** Each hunter produces full `HuntResult` with 18-field `RawFinding` objects from a single harness call.

**Composite Intelligence Principle:** "Rather than generating 100 items at once, generate 10 items ten times with evolving context."

**Two-step pattern:**
1. **LocationScanner** (.harness): `VulnLocation(file_path, start_line, code_snippet, pattern_type)` — 4 fields
2. **FindingEnricher** (.harness per location, parallel): `EnrichedFinding(title, description, cwe_id, severity, confidence, data_flow_summary)` — 6 fields
3. **Assembler** (code): combines into `RawFinding`

**Benefit:** 20 findings → 20 PARALLEL enrichment calls with flat schemas.

**Files:** All `agents/hunt/*.py`, `schemas/hunt.py`
**Effort:** High | **Impact:** Medium
**Dependency:** Depends on #59, after #62

---

#### Route dedup to .ai() — [#64](https://github.com/Agent-Field/sec-af/issues/64)

**Problem:** `dedup.py` uses `.harness()` for pairwise "is A a duplicate of B?" — a simple yes/no decision.

**Schema already exists:** `DuplicateCheck(is_duplicate, duplicate_of, reason)` in `schemas/gates.py`

**Files:** `dedup.py`
**Effort:** Low | **Impact:** Low-Medium
**Dependency:** After #62

---

## v1.3 — Architecture Improvements

### Multi-language support — [#65](https://github.com/Agent-Field/sec-af/issues/65)

**Problem:** Currently Python-focused prompts. Prompts assume Python idioms (e.g., `cursor.execute`, `os.system`).

**Need:** Language detection in recon → language-specific prompt sections (per-language vulnerability patterns, safe idioms to skip, DO NOT FLAG lists).

**Target languages:** Go, TypeScript/JavaScript, Java, Ruby, C#.

**Files:** All `prompts/hunt/*.txt`, `context.py`
**Effort:** Large | **Impact:** High — expands addressable market to all web frameworks
**Dependency:** Depends on #59 (context strings)

---

### Framework-aware analysis — [#66](https://github.com/Agent-Field/sec-af/issues/66)

**Problem:** Django ORM vs raw SQL, Next.js server actions vs API routes, Spring Security annotations. Framework context changes what's a vuln vs intentional.

**Examples:** Don't flag CSRF in Django with `CsrfViewMiddleware` active. Don't flag XSS in React JSX. Don't flag SQLi in Django ORM `filter()`.

**Files:** `agents/recon/architecture.py`, all `prompts/hunt/*.txt`, `context.py`
**Effort:** Large | **Impact:** High — eliminates framework false positives
**Dependency:** Depends on #65 (multi-lang), #59 (context strings)

---

### Incremental / PR-mode scanning — [#67](https://github.com/Agent-Field/sec-af/issues/67)

**Problem:** Full scan is 69 minutes. For CI/CD: diff-aware scanning, cached recon, severity-gated output. Input already supports `base_commit_sha` and `is_pr` flags but they're not wired up.

**Files:** `orchestrator.py`, `config.py`
**Effort:** Large | **Impact:** High — enables CI/CD integration
**Dependency:** Depends on #50 (speed optimization)

---

### Dependency vulnerability reachability — [#68](https://github.com/Agent-Field/sec-af/issues/68)

**Problem:** Dep auditor runs but doesn't correlate CVEs with actual reachability. A known CVE is only real if the vulnerable function is actually called. This is what Endor Labs and Qwiet.ai compete on.

**Schema:** `ReachabilityProof(vulnerable_function: str, call_chain: list[str], reachable: bool, direct: bool)`

**Files:** New `agents/prove/dep_reachability.py`, `schemas/prove.py`
**Effort:** Large | **Impact:** High — competitive differentiator
**Dependency:** Depends on #62 (PROVE decomposition)

---

### DAST-like verification — [#69](https://github.com/Agent-Field/sec-af/issues/69)

**Problem:** Current prove phase does static analysis. True DAST would send exploit payloads and observe responses. For confirmed findings with payloads, optionally run them against a test instance.

**Safety:** Opt-in via flag, sandboxed Docker container, no network, timeout enforcement.

**Files:** New `agents/prove/dast_verifier.py`, `orchestrator.py`
**Effort:** Large | **Impact:** Medium — bulletproof "confirmed" verdicts
**Dependency:** Depends on #62 (PROVE decomposition), sandbox infrastructure

---

## v2.0 — Enterprise & Competitive Moat

### Cross-service attack chains — [#70](https://github.com/Agent-Field/sec-af/issues/70)

Multi-repo input, service mesh awareness, API contract analysis, cross-service data flow tracing.

**Effort:** XL | **Dependency:** #68, #66

---

### Remediation suggestions with code — [#71](https://github.com/Agent-Field/sec-af/issues/71)

Post-prove `.harness()` call to generate concrete fix code (patch diffs). Schema: `RemediationSuggestion(fix_description, patch_diff, confidence)`. Include in SARIF as fix suggestions.

**Effort:** Medium | **Dependency:** #62

---

### Continuous monitoring mode — [#72](https://github.com/Agent-Field/sec-af/issues/72)

Baseline scan + regression detection. Track security posture over time. Alert on new vulnerabilities. Transforms SEC-AF from point-in-time scanner to security platform.

**Effort:** XL | **Dependency:** #67

---

### Custom security policies — [#73](https://github.com/Agent-Field/sec-af/issues/73)

Org-specific rules: "all endpoints must require auth", "no plaintext credentials in config". AI evaluates against custom policies in addition to standard CWEs.

**Effort:** Large | **Dependency:** #66

---

### Compliance report generation (PDF) — [#74](https://github.com/Agent-Field/sec-af/issues/74)

Generate compliance-ready PDF reports with evidence sections, finding details, remediation timelines. We already map to OWASP/PCI-DSS/SOC2/HIPAA/ISO27001.

**Effort:** Medium | **Dependency:** #52

---

## Dependency Graph

```
v1.1 — ALL INDEPENDENT (parallelizable):
  #47  Fix prove phase dropping findings
  #48  Surface recon detections as findings
  #49  Fix schema retry prompt
  #50  Speed optimization ──────────────────────────────────► #67 PR-mode
  #51  Activate strategy selection gate
  #52  Hybrid compliance mapping ───────────────────────────► #74 Compliance PDF
  #53  AI-primary chain detection

v1.2 — DEPENDENCY TREE:
  #54-#58  New hunters (all independent, parallelizable)
  #59  Context strings (no deps) ─┬─► #61 CWE expansion
                                  ├─► #62 PROVE decompose ─┬─► #63 HUNT decompose
                                  ├─► #65 Multi-language    │   #64 Dedup routing
                                  │                         ├─► #68 Dep reachability
                                  │                         ├─► #69 DAST verification
                                  │                         └─► #71 Remediation code
                                  └─► #66 Framework-aware (also needs #65) ─┬─► #70 Cross-service
                                                                             └─► #73 Custom policies
  #60  Reachability gate (no deps)

v1.3 — DEPENDS ON v1.2:
  #65  Multi-lang ──► needs #59
  #66  Framework  ──► needs #65, #59
  #67  PR-mode   ──► needs #50
  #68  Dep reach ──► needs #62
  #69  DAST      ──► needs #62

v2.0 — DEPENDS ON v1.3:
  #70  Cross-service ──► needs #68, #66
  #71  Remediation   ──► needs #62
  #72  Monitoring    ──► needs #67
  #73  Policies      ──► needs #66
  #74  Compliance PDF──► needs #52
```

---

## Parallel Execution Plan (Codex Deployment)

### Wave 1 — v1.1 (all 7 issues, fully parallel)
```
Worktree 1: #47 — Fix prove dropping findings
Worktree 2: #48 — Surface recon detections
Worktree 3: #49 — Fix schema retry prompt
Worktree 4: #50 — Speed optimization
Worktree 5: #51 — Activate strategy gate
Worktree 6: #52 — Hybrid compliance mapping
Worktree 7: #53 — AI-primary chain detection
```

### Wave 2 — v1.2 hunters + context strings (6 issues, fully parallel)
```
Worktree 1: #54 — XSS hunter
Worktree 2: #55 — DoS hunter
Worktree 3: #56 — SSRF hunter
Worktree 4: #57 — Crypto enhanced
Worktree 5: #58 — Business logic hunter
Worktree 6: #59 — Context strings module
```

### Wave 3 — v1.2 Composite Intelligence (depends on #59)
```
Worktree 1: #60 — Reachability gate (independent)
Worktree 2: #61 — CWE expansion (needs #59)
Worktree 3: #62 — PROVE decomposition (needs #59)
```

### Wave 4 — Remaining v1.2 + v1.3 (depends on #62)
```
Worktree 1: #63 — HUNT decomposition (needs #59, #62)
Worktree 2: #64 — Dedup routing (needs #62)
Worktree 3: #65 — Multi-language (needs #59)
Worktree 4: #67 — PR-mode (needs #50)
```

### Wave 5 — v1.3 remaining + v2.0 early
```
Worktree 1: #66 — Framework-aware (needs #65, #59)
Worktree 2: #68 — Dep reachability (needs #62)
Worktree 3: #69 — DAST verification (needs #62)
Worktree 4: #71 — Remediation code (needs #62)
Worktree 5: #74 — Compliance PDF (needs #52)
```

### Wave 6 — v2.0 remaining
```
Worktree 1: #70 — Cross-service chains (needs #68, #66)
Worktree 2: #72 — Continuous monitoring (needs #67)
Worktree 3: #73 — Custom policies (needs #66)
```

---

## What We Explicitly DO NOT Change

| Item | Why It Stays Hardcoded |
|---|---|
| Scoring formula (`scoring.py`) | Arithmetic on AI-determined inputs. Determinism critical for CI gating. |
| SARIF mappings (`sarif.py`) | SARIF 2.1.0 spec — protocol compliance, not domain judgment. |
| Fingerprinting (`sha256` in `dedup.py`) | Deterministic identity. Non-deterministic fingerprints break dedup. |
| Budget allocation (15/35/50%) | Operational tuning, not intelligence. |
| Prover caps (10/30/10K) | Resource limits, not domain knowledge. |
| Default exclude paths | Infrastructure convention. |
| Auth hint keywords (`auth.py`) | Structural string-matching for context extraction. |

---

## Principles Applied

| Composite Intelligence Principle | How This Plan Applies It |
|---|---|
| **Granular Decomposition** | PROVE: 1 call → 4 focused sub-agents (#62). HUNT: 1 call → scan + enrich (#63). |
| **Guided Autonomy** | AI gates get clear constraints (schema + prompt), not open-ended freedom (#51, #61). |
| **Dynamic Orchestration** | Strategy selection adapts to RECON context (#51). Chain detection adapts to findings (#53). |
| **Contextual Fidelity** | String context summaries per strategy instead of JSON dumps (#59). |
| **Asynchronous Parallelism** | PROVE sub-agents 1+2 run in parallel. HUNT enrichers run in parallel per location. |
| **Intelligence Where It Adds Value** | Compliance (#52), chains (#53), strategy routing (#51), business logic (#58) = AI. Scoring, SARIF, fingerprinting = code. |
