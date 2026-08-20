// Package recon ports src/sec_af/agents/recon — the RECON phase of the SEC-AF
// pipeline.
//
// RECON runs five independent harness "mappers" over a repository and folds
// their flat, pipe-delimited output into the structured schemas the HUNT and
// PROVE phases consume:
//
//	run_architecture_mapper        -> schemas.ArchitectureMap
//	run_dependency_auditor         -> schemas.DependencyReport
//	run_config_scanner             -> schemas.ConfigReport
//	run_data_flow_mapper           -> schemas.DataFlowMap        (needs the architecture)
//	run_security_context_profiler  -> schemas.SecurityContext    (needs the architecture)
//
// Python module -> Go file:
//
//	agents/recon/architecture.py       -> architecture.go
//	agents/recon/dependencies.py       -> dependencies.go
//	agents/recon/config_scanner.py     -> config_scanner.go
//	agents/recon/data_flow.py          -> data_flow.go
//	agents/recon/security_context.py   -> security_context.go
//	agents/recon/_parsers.py           -> parsers.go
//	agents/recon/__init__.py           -> recon.go (run_recon / run_fast_recon /
//	                                     run_deep_recon), metrics.go (_repo_metrics),
//	                                     findings.go (extract_recon_findings)
//
// Every mapper follows one shape, so the port does too: build the prompt
// (template + a literal CONTEXT suffix), make a private temp dir named
// `secaf-<agent-name>-*`, run the harness with `Cwd` = that temp dir and
// `ProjectDir` = the repository, extract the `*Raw` model, parse it, and remove
// the temp dir. The prompt strings are byte-verbatim; the golden fixtures under
// testdata/golden are produced from the REAL Python builders by
// go/scripts/gen_golden.py.
package recon
