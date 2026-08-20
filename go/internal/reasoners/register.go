package reasoners

import (
	"context"
	"net/http"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/phases"
)

// register.go mounts the 33 router reasoners onto an *agent.Router, which is
// the Go shape of Python's module-level
//
//	router = AgentRouter(tags=["security", "audit", "red-team"])
//	@router.reasoner()
//	async def run_x(...): ...
//	# app.py: app.include_router(reasoner_router)
//
// The caller (internal/node) does the include with
// agent.RouterOptions{Tags: RouterTags}, so the tags are applied exactly once,
// by the SDK, to every handler in the router.

// RegisterAll registers every router reasoner on r, in DESIGN.md §3 order, and
// returns the ordered names it registered.
//
// The returned slice IS the registration bookkeeping: the SDK keeps
// Agent.reasoners unexported and its /discover payload hardcodes an empty tag
// list per reasoner, so there is no way to read back the ordered surface from
// the SDK. Returning it here (rather than hiding it in a package variable)
// keeps the parity test honest — it asserts what RegisterAll ACTUALLY did, not
// what Names says it should do, and compares the two.
//
// nodeID is read ONCE, here, from phases.NodeID() — Python's module-level
// `NODE_ID = os.getenv("NODE_ID", "sec-af")`, evaluated at import. Every
// `*_phase` handler closes over that value, so the `.call` targets are fixed
// for the life of the process.
func RegisterAll(r *agent.Router, app appx.App) []string {
	nodeID := phases.NodeID()
	reg := &registrar{router: r}

	// --- reasoners/recon.py -------------------------------------------------
	register(reg, app, NameRunArchitectureMapper, RunArchitectureMapper)
	register(reg, app, NameRunDependencyAuditor, RunDependencyAuditor)
	register(reg, app, NameRunConfigScanner, RunConfigScanner)
	register(reg, app, NameRunDataFlowMapper, RunDataFlowMapper)
	register(reg, app, NameRunSecurityContextProfiler, RunSecurityContextProfiler)

	// --- reasoners/hunt.py --------------------------------------------------
	register(reg, app, NameRunInjectionHunter, RunInjectionHunter)
	register(reg, app, NameRunDosHunter, RunDosHunter)
	register(reg, app, NameRunSSRFHunter, RunSSRFHunter)
	register(reg, app, NameRunAuthHunter, RunAuthHunter)
	register(reg, app, NameRunXSSHunter, RunXSSHunter)
	register(reg, app, NameRunCryptoHunter, RunCryptoHunter)
	register(reg, app, NameRunBusinessLogicHunter, RunBusinessLogicHunter)
	register(reg, app, NameRunLogicBugsHunter, RunLogicBugsHunter)
	register(reg, app, NameRunDataExposureHunter, RunDataExposureHunter)
	register(reg, app, NameRunSupplyChainHunter, RunSupplyChainHunter)
	register(reg, app, NameRunConfigSecretsHunter, RunConfigSecretsHunter)
	register(reg, app, NameRunAPISecurityHunter, RunAPISecurityHunter)
	register(reg, app, NameRunDeduplicator, RunDeduplicator)

	// --- reasoners/prove.py -------------------------------------------------
	register(reg, app, NameRunDepReachability, RunDepReachability)
	register(reg, app, NameRunVerifier, RunVerifier)
	register(reg, app, NameRunTracer, RunTracer)
	register(reg, app, NameRunSanitizationAnalyzer, RunSanitizationAnalyzer)
	register(reg, app, NameRunExploitHypothesizer, RunExploitHypothesizer)
	register(reg, app, NameRunVerdictAgent, RunVerdictAgent)
	register(reg, app, NameRunRemediation, RunRemediation)
	register(reg, app, NameRunRemediationAgent, RunRemediationAgent)
	register(reg, app, NameRunDastVerifier, RunDastVerifier)
	register(reg, app, NameRunCrossServiceAnalyzer, RunCrossServiceAnalyzer)

	// --- reasoners/phases.py ------------------------------------------------
	register(reg, app, NameRunCWEExpansion, RunCWEExpansion)
	registerPhase(reg, app, nodeID, NameReconPhase, ReconPhase)
	registerPhase(reg, app, nodeID, NameHuntPhase, HuntPhase)
	registerPhase(reg, app, nodeID, NameProvePhase, ProvePhase)
	registerPhase(reg, app, nodeID, NameRemediationPhase, RemediationPhase)

	return reg.names
}

// registrar is the single registration path: everything that reaches the router
// is recorded, so the bookkeeping cannot drift from what the SDK receives.
type registrar struct {
	router *agent.Router
	names  []string
}

// add mounts one reasoner, recording it, wrapping it in the SDK-level input
// validation Python performs, and attaching the input schema the Python node
// publishes for that name.
//
// The schema is NOT optional: the Go SDK defaults every reasoner to
// `{"type":"object","additionalProperties":true}`, which would make this node's
// discovery payload strictly less informative than the Python one it replaces.
// InputSchema panics on a name the capture does not know, so a reasoner added
// here without regenerating testdata/python_input_schemas.json fails at
// registration rather than shipping the placeholder. See input_schemas.go.
func (r *registrar) add(name string, h agent.HandlerFunc) {
	r.names = append(r.names, name)
	r.router.RegisterReasoner(name, ValidateHandler(name, h), agent.WithInputSchema(InputSchema(name)))
}

// ValidateHandler wraps h with `_validate_handler_input` for the reasoner
// called name — the check the Python SDK runs on every request body BEFORE the
// handler function is entered (agent.py:3120-3134).
//
// Exported because internal/node registers the `audit` reasoner on the Agent
// itself rather than on this router, and it is the same layer: all 34 handlers
// on the node's surface are validated, or the port has a hole exactly where a
// control-plane caller reaches in.
//
// Python answers a failure with `JSONResponse(422, {"detail": safe_message})`
// from the endpoint, so the handler never runs. The Go SDK has no pre-handler
// hook, so the check runs as the first thing INSIDE the handler and reports the
// same status through agent.ExecuteError — the SDK writes
// `{"error": <message>}` with that code (agent.go:1259-1273). Same status, same
// message, different body key; the execution is additionally recorded as a
// failure, which Python's earlier rejection avoids.
func ValidateHandler(name string, h agent.HandlerFunc) agent.HandlerFunc {
	// Resolve the spec at REGISTRATION time so an unknown name panics at boot,
	// not on the first request — the same loud-drift contract InputSchema has.
	_ = handlerSpecFor(name)
	return func(ctx context.Context, input map[string]any) (any, error) {
		validated, err := ValidateHandlerInput(name, input)
		if err != nil {
			return nil, HandlerInputExecuteError(err)
		}
		return h(ctx, validated)
	}
}

// HandlerInputExecuteError maps a *HandlerInputError onto the SDK error that
// makes the node answer 422, the status Python's endpoint returns.
func HandlerInputExecuteError(err error) error {
	return &agent.ExecuteError{StatusCode: http.StatusUnprocessableEntity, Message: err.Error()}
}

// register adapts a typed reasoner function to the SDK HandlerFunc: afx.Bind
// the untyped request map into T (running T's default-seeding UnmarshalJSON, so
// the Python keyword defaults apply to absent keys) and hand it to fn. T is
// inferred from fn.
func register[T any](
	r *registrar,
	app appx.App,
	name string,
	fn func(context.Context, appx.App, T) (map[string]any, error),
) {
	r.add(name, func(ctx context.Context, input map[string]any) (any, error) {
		in, err := afx.Bind[T](input)
		if err != nil {
			return nil, err
		}
		return fn(ctx, app, in)
	})
}

// registerPhase is register for the four `*_phase` reasoners, which additionally
// need the node id their `.call` targets are prefixed with.
func registerPhase[T any](
	r *registrar,
	app appx.App,
	nodeID string,
	name string,
	fn func(context.Context, appx.App, string, T) (map[string]any, error),
) {
	r.add(name, func(ctx context.Context, input map[string]any) (any, error) {
		in, err := afx.Bind[T](input)
		if err != nil {
			return nil, err
		}
		return fn(ctx, app, nodeID, in)
	})
}
