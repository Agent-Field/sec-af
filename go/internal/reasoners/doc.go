// Package reasoners ports src/sec_af/reasoners/{__init__,recon,hunt,prove}.py —
// the thin adapter layer between the control plane's reasoner surface and the
// in-process agent functions under internal/agents.
//
// Python builds that surface with a module-level router:
//
//	router = AgentRouter(tags=["security", "audit", "red-team"])   # __init__.py
//
//	@router.reasoner()
//	async def run_architecture_mapper(repo_path: str) -> dict[str, Any]:
//	    router.note("Architecture mapper starting", tags=["recon", "architecture"])
//	    result = await _run_architecture_mapper(router, repo_path)
//	    return result.model_dump()
//
// Every adapter does the same four things, and this package reproduces them one
// for one:
//
//  1. emit the reasoner's "X starting" note with its exact tags (a few carry
//     none — see NameRunLogicBugsHunter and NameRunCWEExpansion);
//  2. materialize the untyped request body into the pydantic models the agent
//     function expects (afx.Bind over a typed input struct whose json tags and
//     defaults are the Python signature, plus the required-field checks pydantic
//     performs — validate.go);
//  3. call the agent function;
//  4. return `result.model_dump()` as a map (afx.ToMap).
//
// # Input validation
//
// Step 2 is not the first thing a request meets. The Python SDK runs
// `Agent._validate_handler_input` over the body BEFORE the decorated function
// is entered, answering 422 for a null on a required parameter and COERCING
// scalars (`"50"` -> 50, `5` -> "5", `"yes"` -> true). The Go SDK has no such
// layer, so handler_input.go ports it and RegisterAll wraps every handler in
// it — internal/node does the same for `audit`. Without it the node accepted
// bodies Python 422s and rejected bodies Python accepts, on all 34 reasoners of
// the registered surface.
//
// # Registration
//
// RegisterAll mounts the 33 router reasoners onto an *agent.Router in the
// canonical DESIGN.md §3 order; internal/node mounts that router with
// agent.RouterOptions{Tags: RouterTags} (the AgentRouter(tags=...) equivalent)
// and registers the 34th reasoner, the externally driven `audit`, directly on
// the agent. The SDK's Agent keeps its reasoner table unexported and its
// discovery payload hardcodes an empty tag list, so RegisterAll returns its own
// ordered bookkeeping — the source of truth the parity test asserts (the same
// approach pr-af's Node.RegisteredNames takes).
//
// # Input schemas
//
// Python publishes a JSON Schema per reasoner, derived from the decorated
// function's signature. The Go SDK has no such derivation and would otherwise
// publish a placeholder, so the exact schemas the Python node registers are
// committed as testdata/python_input_schemas.json and replayed verbatim through
// InputSchema — including Python's own derivation quirks. input_schemas.go
// documents them and how to regenerate the capture.
//
// A SECOND capture, testdata/python_input_types.json, holds the raw
// `(annotation, default)` pairs the same signatures produce — the input
// `_validate_handler_input` runs on. The two are derived by different SDK code
// paths from the same source, and handler_input_test.go asserts they agree.
//
// # What is NOT here
//
// The `*_phase` bodies (the four reasoners that ARE the control-plane DAG) live
// in internal/phases; this package only binds their inputs and threads the node
// id. `run_cwe_expansion` likewise delegates to phases.RunCWEExpansion. Keeping
// the split means a phase can be tested without the registration layer and vice
// versa.
package reasoners
