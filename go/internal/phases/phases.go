package phases

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/aix"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// The keyword defaults the four phase reasoners declare. Go has no default
// arguments, so the registration adapters name them explicitly; keeping them
// here means the Python contract is stated once.
const (
	// DefaultDepth ports `depth: str = "standard"` on recon_phase, hunt_phase
	// and prove_phase.
	DefaultDepth = "standard"
	// DefaultMaxConcurrentHunters ports hunt_phase's `max_concurrent_hunters: int = 4`.
	DefaultMaxConcurrentHunters = 4
	// DefaultEarlyStopFileThreshold ports hunt_phase's
	// `early_stop_file_threshold: int = 30`. Unlike agents/hunt's identically
	// named parameter this one IS observable: it becomes the
	// `max_files_without_signal` kwarg on every hunter `.call`.
	DefaultEarlyStopFileThreshold = 30
	// DefaultMaxConcurrentProvers ports prove_phase's `max_concurrent_provers: int = 3`.
	DefaultMaxConcurrentProvers = 3
	// DefaultMaxConcurrentRemediations ports remediation_phase's
	// `max_concurrent_remediations: int = 3`.
	DefaultMaxConcurrentRemediations = 3
)

// NodeID reproduces `NODE_ID = os.getenv("NODE_ID", "sec-af")`
// (reasoners/phases.py:31) — the prefix every `.call` target carries.
//
// Python reads the variable ONCE at import time; Go reads it per call, which
// only differs for a process that mutates its own environment after start (none
// does). Callers thread the result through the phase functions so tests can pin
// it.
//
// DOCUMENTED DIVERGENCE, empty string only. `os.getenv("NODE_ID", "sec-af")`
// returns "" for an explicitly-empty variable (`NODE_ID=`, the shape a
// docker-compose `NODE_ID=${NODE_ID}` passthrough produces). Python is at
// least SELF-CONSISTENT there — app.py:32 and reasoners/phases.py:31 use the
// same expression, so the registered node id and the `.call` prefix are always
// the identical string. Go cannot register as "": the SDK rejects an empty
// agent.Config.NodeID. So this reader treats "" as unset, exactly like
// node.envOr, which keeps the ONE invariant that matters intact — the id the
// node registers under and the prefix its DAG edges carry can never disagree.
// Reading os.LookupEnv here instead would boot a node registered as "sec-af"
// whose every `.call` targeted ".recon_phase", failing mid-audit instead of at
// boot.
func NodeID() string {
	if v := os.Getenv("NODE_ID"); v != "" {
		return v
	}
	return "sec-af"
}

// normalizeDepth ports `_normalize_depth` (reasoners/phases.py:52):
//
//	try:    return DepthProfile(depth.lower())
//	except ValueError: return DepthProfile.STANDARD
//
// config.NormalizeDepth is the same lenient mapping.
func normalizeDepth(depth string) config.DepthProfile { return config.NormalizeDepth(depth) }

// callMap performs one DAG edge:
//
//	raw = await _runtime_router.call(f"{NODE_ID}.{name}", **kwargs)
//	payload = _as_dict(_unwrap(raw, name), name)
//
// name is BOTH the reasoner name appended to nodeID and the label the
// _unwrap/_as_dict error strings carry, exactly as in Python where the same
// literal is used twice.
func callMap(ctx context.Context, app appx.Caller, nodeID, name string, input map[string]any) (map[string]any, error) {
	raw, err := app.Call(ctx, nodeID+"."+name, input)
	if err != nil {
		return nil, err
	}
	payload, err := afx.Unwrap(raw, name)
	if err != nil {
		return nil, err
	}
	return afx.AsMap(payload, name)
}

// callBindWith is callMap followed by `Model.model_validate(payload)`, with the
// binder named explicitly.
//
// There is deliberately NO afx.Bind-based shorthand. afx.Bind is a JSON round
// trip: it cannot express "required", so it accepts payloads pydantic rejects
// and zero-fills the missing fields (afx/bind.go). Every `.call` boundary in
// this package therefore names one of validate.go's checked binders — including
// the four recon children, whose models have no required field of their OWN but
// whose LISTS hold models that do.
func callBindWith[T any](
	ctx context.Context,
	app appx.Caller,
	nodeID, name string,
	input map[string]any,
	bind func(map[string]any) (T, error),
) (T, error) {
	var zero T
	payload, err := callMap(ctx, app, nodeID, name, input)
	if err != nil {
		return zero, err
	}
	return bind(payload)
}

// ---------------------------------------------------------------------------
// _recon_summary_string
// ---------------------------------------------------------------------------

// ReconSummaryString ports `_recon_summary_string` (reasoners/phases.py:59) —
// the natural-language recon digest hunt_phase feeds to the AI strategy gate:
//
//	"python/typescript (django), 5000 LOC, 42 files, jwt auth, 5 direct dependencies"
//
// Every guard is Python TRUTHINESS, which is where the subtleties live:
//
//   - `if recon.languages` / `if recon.frameworks` — an empty list contributes
//     nothing, and the frameworks parenthetical only appears when BOTH are
//     non-empty. Neither list is filtered, so a blank entry survives into the
//     "/"-join.
//   - `if recon.security_context.auth_model` — an EMPTY auth model is skipped
//     entirely; it is not rendered as " auth".
//   - the three counter guards are `> 0` comparisons, so a negative count
//     (impossible from pydantic, but not from a hand-built struct) is skipped
//     rather than rendered.
//   - the fallback for an all-empty recon is the literal "Unknown application".
//
// The integers are Python `str(int)`, i.e. plain decimal — no thousands
// separators — which strconv.Itoa reproduces.
func ReconSummaryString(recon schemas.ReconResult) string {
	parts := make([]string, 0, 10)

	if len(recon.Languages) > 0 {
		langStr := strings.Join(recon.Languages, "/")
		if len(recon.Frameworks) > 0 {
			parts = append(parts, langStr+" ("+strings.Join(recon.Frameworks, "/")+")")
		} else {
			parts = append(parts, langStr)
		}
	}

	if recon.LinesOfCode > 0 {
		parts = append(parts, strconv.Itoa(recon.LinesOfCode)+" LOC")
	}
	if recon.FileCount > 0 {
		parts = append(parts, strconv.Itoa(recon.FileCount)+" files")
	}

	if recon.SecurityContext.AuthModel != "" {
		parts = append(parts, recon.SecurityContext.AuthModel+" auth")
	}
	if len(recon.SecurityContext.CryptoUsage) > 0 {
		parts = append(parts, strconv.Itoa(len(recon.SecurityContext.CryptoUsage))+" crypto algorithms")
	}

	if recon.Dependencies.DirectCount > 0 {
		parts = append(parts, strconv.Itoa(recon.Dependencies.DirectCount)+" direct dependencies")
	}
	if len(recon.Dependencies.KnownCves) > 0 {
		parts = append(parts, strconv.Itoa(len(recon.Dependencies.KnownCves))+" known CVEs")
	}

	if len(recon.Architecture.APISurface) > 0 {
		parts = append(parts, strconv.Itoa(len(recon.Architecture.APISurface))+" API endpoints")
	}

	if len(recon.Config.Secrets) > 0 {
		parts = append(parts, strconv.Itoa(len(recon.Config.Secrets))+" secrets found")
	}
	if len(recon.Config.Misconfigs) > 0 {
		parts = append(parts, strconv.Itoa(len(recon.Config.Misconfigs))+" misconfigs")
	}

	if len(parts) == 0 {
		return "Unknown application"
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// expand_cwes_for_hunt / run_cwe_expansion
// ---------------------------------------------------------------------------

// CWEExpansionPrompt builds the exact user prompt `expand_cwes_for_hunt` sends
// to `.ai(schema=CWEExpansion)` (reasoners/phases.py:117).
//
// It is a separate function only so the golden test can compare the bytes
// without scripting an AI response; ExpandCWEsForHunt is the single caller.
// `", ".join(strategies)` renders an empty list as the empty string, so an
// empty strategy list yields the line "Active strategies: " with a trailing
// space.
func CWEExpansionPrompt(reconSummary string, strategies []string) string {
	return "Based on this codebase recon context, suggest additional CWE IDs that hunters should look for " +
		"beyond their hardcoded baselines. Only suggest CWEs that are specifically relevant to " +
		"the detected languages, frameworks, and architecture patterns.\n\n" +
		"Active strategies: " + strings.Join(strategies, ", ") + "\n\n" +
		"Recon context:\n" + reconSummary
}

// ExpandCWEsForHunt ports `expand_cwes_for_hunt` (reasoners/phases.py:109):
//
//	try:
//	    result = await router.ai(user=prompt, schema=CWEExpansion)
//	    ...
//	    return expansion.additional_cwes
//	except Exception:
//	    return []            # graceful fallback — AI expansion is additive
//
// Python parity:
//
//   - EVERY failure is swallowed and yields an empty list. That is the whole
//     point of the helper: a dead AI gate must not fail the hunt. Go therefore
//     returns no error — the signature carries the same information the Python
//     caller has.
//   - the two `isinstance` branches are Python duck-typing over an SDK that may
//     hand back either the model or a raw dict; aix.Structured always parses
//     into the typed value, so both collapse into one path.
//   - a successful call whose `additional_cwes` is absent yields `[]` (pydantic
//     default_factory=list, reproduced by the schemas package's default
//     seeding), NOT nil — the caller's `if additional_cwes:` guard treats them
//     the same, but the returned slice is non-nil so a JSON round trip spells
//     it "[]".
func ExpandCWEsForHunt(ctx context.Context, app appx.AIer, reconSummary string, strategies []string) []string {
	prompt := CWEExpansionPrompt(reconSummary, strategies)

	expansion, err := aix.Structured[schemas.CWEExpansion](ctx, app, "", prompt)
	if err != nil {
		return []string{}
	}
	if expansion.AdditionalCwes == nil {
		return []string{}
	}
	return expansion.AdditionalCwes
}

// RunCWEExpansion ports the `run_cwe_expansion` reasoner body
// (reasoners/phases.py:140):
//
//	additional = await expand_cwes_for_hunt(recon_summary, strategies)
//	return {"additional_cwes": additional}
//
// Registered on the router but never `.call`ed by any phase — hunt_phase calls
// expand_cwes_for_hunt in process — so it contributes no DAG node. It returns
// no error for the same reason ExpandCWEsForHunt does not.
func RunCWEExpansion(ctx context.Context, app appx.AIer, reconSummary string, strategies []string) map[string]any {
	return map[string]any{"additional_cwes": ExpandCWEsForHunt(ctx, app, reconSummary, strategies)}
}
