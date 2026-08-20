// Package prove ports src/sec_af/agents/prove — the PROVE phase.
//
// PROVE takes the provisional findings HUNT produced and decides, per finding,
// whether the vulnerability is real: it traces the data flow, analyses the
// sanitization on that path, hypothesises an exploit, asks a judgment model for
// a verdict, and assembles the evidence into a schemas.VerifiedFinding.
//
// Module map (Python file -> Go file):
//
//	__init__.py       prove.go          _priority_sort, _apply_metadata,
//	                                    _run_parallel_verification, run_prove,
//	                                    run_prove_streaming
//	verifier.py       verifier.go       run_verifier (the in-process
//	                                    tracer -> sanitization -> exploit ->
//	                                    verdict chain), fallback
//	assembler.py      assembler.go      assemble_verified_finding
//	tracer.py         tracer.go         run_tracer
//	sanitization.py   sanitization.go   run_sanitization_analyzer
//	exploit.py        exploit.go        run_exploit_hypothesizer
//	verdict.py        verdict.go        run_verdict_agent (.ai, not .harness)
//	chain_builder.py  chain_builder.go  run_chain_builder (schema-less harness)
//	cross_service.py  cross_service.go  run_cross_service_analyzer
//	dast_verifier.py  dast_verifier.go  run_dast_verifier
//	dep_reachability.py dep_reachability.go run_dep_reachability
//	sandbox.py        sandbox.go        run_sandboxed
//
// DAG note (DESIGN.md §3): every function here is called IN PROCESS. The
// control-plane `.call(...)` fan-out that produces the DAG's `run_verifier`
// nodes lives in internal/phases (Python: reasoners/phases.py prove_phase);
// this package is what those reasoners execute once routed. Nothing in here
// may grow an app.Call — that would double the DAG.
//
// Every exported function takes ctx first and the narrowest appx sub-interface
// it needs (Harnesser, AIer, or the union HarnessAIer), because Python passes
// the SDK agent/router and only ever touches `.harness(...)` / `.ai(...)`.
package prove
