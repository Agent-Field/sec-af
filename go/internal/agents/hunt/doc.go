// Package hunt ports src/sec_af/agents/hunt — the HUNT phase: twelve hunter
// modules, the two-step scan/enrich harness pipeline they share, and the
// run_hunt / run_hunt_streaming orchestration in that package's __init__.py.
//
// # Shape of a hunter
//
// Every hunter is the same four steps (agents/hunt/_scan_enrich.py):
//
//  1. build a scan prompt: load its own prompt template, substitute a recon
//     context (and, for most, the language/framework hint blocks), then append
//     a CONTEXT block whose exact wording differs per hunter;
//  2. ScanLocations — one harness call with the ScanLocationsResult schema,
//     which returns bare VulnLocations. An empty list short-circuits;
//  3. EnrichLocationsParallel — one harness call per location, at most five at
//     a time, each producing an EnrichedFinding;
//  4. AssembleFinding — zip the two lists and coerce them into RawFindings.
//
// # Two Python quirks reproduced here
//
// ARGUMENT CASCADE. `_run_single_hunter` does not know the hunters' signatures.
// It tries five different call shapes in order, moving on whenever Python
// raises TypeError, and the FIRST shape that binds wins:
//
//	shape 1  runner(app=, repo_path=, recon_result=, depth=, depth_prompt=,
//	                max_files_without_signal=, include_paths=)
//	shape 2  runner(app=, repo_path=, recon_result=, depth=)
//	shape 3  runner(app=, repo_path=, recon_result=, max_files_without_signal=)
//	shape 4  runner(app, repo_path, recon_result, depth.value)   [positional]
//	shape 5  runner(app, repo_path, recon_result)                [positional]
//
// No hunter accepts `include_paths` or all of shape 1's keywords, so shape 1
// never binds. Shape 3 never binds either — the hunters that omit `depth` name
// their third parameter `recon`, not `recon_result`. What is left:
//
//   - injection, xss, dos, ssrf, auth, business_logic declare
//     `(app, repo_path, recon_result, depth, max_files_without_signal=30, ...)`
//     and bind at shape 2, so max_files_without_signal keeps its own default of
//     30 and business_logic's depth_prompt keeps its default of "";
//   - crypto, data_exposure, supply_chain, config_secrets, api_security declare
//     `(app, repo_path, recon, max_files_without_signal=30)` and bind at shape
//     4 — POSITIONALLY. The fourth positional argument is `depth.value`, so
//     these five hunters receive the DEPTH STRING in their
//     max_files_without_signal slot. Python never type-checks it, and the value
//     is only ever interpolated into the prompt, so their early-stop rule reads
//     "if you inspect standard files without credible crypto misuse".
//
// That is not a bug this port fixes; it is what reaches the LLM today, and the
// goldens under testdata/golden pin it (see prompt_crypto_standard.txt). It
// also makes run_hunt's early_stop_file_threshold parameter DEAD: it is only
// ever passed in shapes 1 and 3, neither of which binds. The Go table in
// hunt.go encodes the settled result of the cascade directly, one closure per
// strategy, rather than re-deriving it at run time.
//
// MISSING-HUNTER STUBS. `_load_hunter` swallows ImportError and substitutes an
// async no-op that returns []. That is not dead code: each hunter module
// imports sec_af.context, and sec_af.context imports back into
// sec_af.agents.hunt._framework_hints, so whichever of the two packages is
// imported FIRST decides the outcome. Import sec_af.agents.hunt first (which is
// what the live node does, app.py -> orchestrator.py -> `.agents.hunt`) and all
// eleven hunters load; import sec_af.context first and all eleven silently
// become no-ops. The Go port has no such hazard — the table is a package-level
// slice of direct references — so the stubs are not ported, only recorded here.
// go/scripts/gen_golden.py forces the correct order and asserts it.
//
// # Package boundaries
//
// The language/framework hint tables live in internal/recontext, not here,
// even though Python declares them in agents/hunt/_framework_hints.py and
// _language_hints.py: internal/recontext is what every hunter needs for its
// recon context, so hosting the tables there is what breaks the import cycle
// Go would otherwise reject. See internal/recontext/hints.go.
package hunt
