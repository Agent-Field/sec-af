package reasoners

// names.go declares the SEC-AF reasoner surface: the 33 names the Python
// AgentRouter registers (reasoners/recon.py, hunt.py, prove.py, phases.py) plus
// the one top-level `audit` reasoner app.py registers on the agent itself.
//
// The constants exist so a registration, a `.call` target and a test all spell
// a reasoner the same way; Names fixes the ORDER, which DESIGN.md §3 pins.

// The 33 router reasoner names, in DESIGN.md §3 order. The order is the Python
// import order of reasoners/__init__.py (recon -> hunt -> prove -> phases) and,
// within each module, the order the `@router.reasoner()` decorators appear.
const (
	// --- reasoners/recon.py ---

	NameRunArchitectureMapper      = "run_architecture_mapper"
	NameRunDependencyAuditor       = "run_dependency_auditor"
	NameRunConfigScanner           = "run_config_scanner"
	NameRunDataFlowMapper          = "run_data_flow_mapper"
	NameRunSecurityContextProfiler = "run_security_context_profiler"

	// --- reasoners/hunt.py ---

	NameRunInjectionHunter     = "run_injection_hunter"
	NameRunDosHunter           = "run_dos_hunter"
	NameRunSSRFHunter          = "run_ssrf_hunter"
	NameRunAuthHunter          = "run_auth_hunter"
	NameRunXSSHunter           = "run_xss_hunter"
	NameRunCryptoHunter        = "run_crypto_hunter"
	NameRunBusinessLogicHunter = "run_business_logic_hunter"
	// NameRunLogicBugsHunter is an ALIAS reasoner: its Python body forwards to
	// run_business_logic_hunter (the reasoner, not the agent function), so it
	// emits no note of its own and its DAG child is indistinguishable from a
	// direct run_business_logic_hunter call.
	NameRunLogicBugsHunter     = "run_logic_bugs_hunter"
	NameRunDataExposureHunter  = "run_data_exposure_hunter"
	NameRunSupplyChainHunter   = "run_supply_chain_hunter"
	NameRunConfigSecretsHunter = "run_config_secrets_hunter"
	NameRunAPISecurityHunter   = "run_api_security_hunter"
	NameRunDeduplicator        = "run_deduplicator"

	// --- reasoners/prove.py ---

	NameRunDepReachability      = "run_dep_reachability"
	NameRunVerifier             = "run_verifier"
	NameRunTracer               = "run_tracer"
	NameRunSanitizationAnalyzer = "run_sanitization_analyzer"
	NameRunExploitHypothesizer  = "run_exploit_hypothesizer"
	NameRunVerdictAgent         = "run_verdict_agent"
	NameRunRemediation          = "run_remediation"
	NameRunRemediationAgent     = "run_remediation_agent"
	NameRunDastVerifier         = "run_dast_verifier"
	NameRunCrossServiceAnalyzer = "run_cross_service_analyzer"

	// --- reasoners/phases.py ---

	// NameRunCWEExpansion is REGISTERED but never `.call`ed: hunt_phase invokes
	// expand_cwes_for_hunt in process (an `.ai()` call), so this reasoner
	// contributes no DAG node. See DESIGN.md §3.
	NameRunCWEExpansion = "run_cwe_expansion"

	NameReconPhase       = "recon_phase"
	NameHuntPhase        = "hunt_phase"
	NameProvePhase       = "prove_phase"
	NameRemediationPhase = "remediation_phase"
)

// NameAudit is the ONE externally driven reasoner. Python registers it with
// `@app.reasoner()` on the Agent, not on the AgentRouter, so it carries none of
// the router's tags. internal/node owns its handler.
const NameAudit = "audit"

// Names is the canonical ordered list of the 33 router reasoner names —
// DESIGN.md §3's list verbatim. RegisterAll registers exactly these, in exactly
// this order, and returns the same slice content as its bookkeeping.
var Names = []string{
	NameRunArchitectureMapper,
	NameRunDependencyAuditor,
	NameRunConfigScanner,
	NameRunDataFlowMapper,
	NameRunSecurityContextProfiler,
	NameRunInjectionHunter,
	NameRunDosHunter,
	NameRunSSRFHunter,
	NameRunAuthHunter,
	NameRunXSSHunter,
	NameRunCryptoHunter,
	NameRunBusinessLogicHunter,
	NameRunLogicBugsHunter,
	NameRunDataExposureHunter,
	NameRunSupplyChainHunter,
	NameRunConfigSecretsHunter,
	NameRunAPISecurityHunter,
	NameRunDeduplicator,
	NameRunDepReachability,
	NameRunVerifier,
	NameRunTracer,
	NameRunSanitizationAnalyzer,
	NameRunExploitHypothesizer,
	NameRunVerdictAgent,
	NameRunRemediation,
	NameRunRemediationAgent,
	NameRunDastVerifier,
	NameRunCrossServiceAnalyzer,
	NameRunCWEExpansion,
	NameReconPhase,
	NameHuntPhase,
	NameProvePhase,
	NameRemediationPhase,
}

// RouterTags ports `AgentRouter(tags=["security", "audit", "red-team"])`
// (reasoners/__init__.py:4). internal/node passes it as
// agent.RouterOptions{Tags: RouterTags}, which the SDK merges into every
// handler the router carries — the Go equivalent of the AgentRouter's
// tag inheritance.
//
// These are SEMANTIC domain tags, not node-identity tags: callers reach this
// node through node_id=sec-af, e.g. `sec-af.audit`.
var RouterTags = []string{"security", "audit", "red-team"}
