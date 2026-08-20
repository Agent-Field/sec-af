// Package phases ports src/sec_af/reasoners/phases.py — the four `*_phase`
// reasoners that ARE the SEC-AF control-plane DAG, plus the two helpers that
// live in the same module (`_recon_summary_string`, `expand_cwes_for_hunt`) and
// the `run_cwe_expansion` reasoner body.
//
// # Why these functions look different from internal/agents/*
//
// Everything under internal/agents runs IN PROCESS: run_hunt calls each hunter
// as a Python function, so the control plane sees one execution. The phase
// reasoners instead reach every sub-agent through
// `await router.call(f"{NODE_ID}.run_x", **kwargs)`, which the control plane
// turns into a tracked CHILD execution — that is what draws the DAG in the UI:
//
//	audit
//	├── recon_phase
//	│   ├── run_architecture_mapper ┐
//	│   ├── run_dependency_auditor  ├ gather (3)
//	│   ├── run_config_scanner      ┘
//	│   ├── run_data_flow_mapper           ┐ gather (2) — skipped when depth == quick
//	│   └── run_security_context_profiler  ┘
//	├── hunt_phase
//	│   ├── run_<strategy>_hunter × N   semaphore max(1, min(max_concurrent_hunters, N))
//	│   └── run_deduplicator            only when ≥1 fingerprint-unique finding
//	├── prove_phase
//	│   └── run_verifier × K            K = min(len(findings), prover cap)  semaphore 3
//	└── remediation_phase
//	    └── run_remediation × M         M = confirmed/likely without remediation
//
// So every `.call` in the Python source is an app.Call here, with the SAME
// target name and the SAME kwargs keys — never a direct Go function call, which
// would collapse the DAG (DESIGN.md §0.3). Conversely `expand_cwes_for_hunt` is
// an `.ai()` call in Python and stays an aix.Structured here: `run_cwe_expansion`
// is REGISTERED as a reasoner but never `.call`ed, so it is not a DAG node.
//
// # Signatures are the reasoner input contract
//
// Each exported phase function keeps the Python signature's parameter names and
// order, and Go's lack of default arguments means the caller (internal/reasoners)
// passes the Python defaults explicitly. The named constants below spell them
// out so a registration adapter cannot drift from the Python contract:
//
//	recon_phase(repo_path, depth="standard")
//	hunt_phase(repo_path, recon_context, depth="standard", ai_gate=None,
//	           max_concurrent_hunters=4, early_stop_file_threshold=30)
//	prove_phase(repo_path, hunt_result, depth="standard", max_provers=None,
//	            max_concurrent_provers=3)
//	remediation_phase(repo_path, verified_findings, max_concurrent_remediations=3)
//
// Every function additionally takes ctx (first), an appx sub-interface for the
// app the Python module reaches through its module-global `_runtime_router`,
// and the nodeID that Python reads once from the NODE_ID environment variable.
// Threading nodeID as a parameter rather than a package global is what lets a
// test assert the exact target strings; NodeID() reproduces the Python default
// for production wiring.
package phases
