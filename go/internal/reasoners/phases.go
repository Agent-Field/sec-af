package reasoners

import (
	"context"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/phases"
)

// phases.go ports the five reasoner ENTRY POINTS declared in
// src/sec_af/reasoners/phases.py. The bodies live in internal/phases; these
// adapters only bind the request and thread the node id.
//
// nodeID is a parameter rather than a package variable so a test can pin the
// `.call` targets. RegisterAll reads phases.NodeID() ONCE and closes over the
// result, which is Python's `NODE_ID = os.getenv("NODE_ID", "sec-af")` at
// module import: a node that starts with NODE_ID=sec-af-go keeps calling
// sec-af-go.* for its whole life even if the variable is later changed.

// RunCWEExpansion ports `run_cwe_expansion(recon_summary, strategies)`
// (reasoners/phases.py:139):
//
//	additional = await expand_cwes_for_hunt(recon_summary, strategies)
//	return {"additional_cwes": additional}
//
// Python parity: no note, and no error path — expand_cwes_for_hunt swallows
// every failure and returns []. It is registered but never `.call`ed
// (hunt_phase runs expand_cwes_for_hunt in process), so it draws no DAG node.
func RunCWEExpansion(ctx context.Context, app appx.App, in CWEExpansionInput) (map[string]any, error) {
	return phases.RunCWEExpansion(ctx, app, in.ReconSummary, in.Strategies), nil
}

// ReconPhase ports the `recon_phase` reasoner (reasoners/phases.py:152).
func ReconPhase(ctx context.Context, app appx.App, nodeID string, in ReconPhaseInput) (map[string]any, error) {
	return phases.ReconPhase(ctx, app, nodeID, in.RepoPath, in.Depth)
}

// HuntPhase ports the `hunt_phase` reasoner (reasoners/phases.py:239).
//
// Python parity: `ai_gate` is always None on the live path (app.py's `.call`
// omits it), so phases.NewJSONAIGate yields nil there. A direct caller that
// supplies one takes the `ai_gate is not None` branch and gets the
// "AI gate failed: ..." note — see HuntPhaseInput.
func HuntPhase(ctx context.Context, app appx.App, nodeID string, in HuntPhaseInput) (map[string]any, error) {
	return phases.HuntPhase(
		ctx, app, nodeID,
		in.RepoPath,
		in.ReconContext,
		in.Depth,
		phases.NewJSONAIGate(in.AIGate),
		in.MaxConcurrentHunters,
		in.EarlyStopFileThreshold,
	)
}

// ProvePhase ports the `prove_phase` reasoner (reasoners/phases.py:381).
func ProvePhase(ctx context.Context, app appx.App, nodeID string, in ProvePhaseInput) (map[string]any, error) {
	return phases.ProvePhase(
		ctx, app, nodeID,
		in.RepoPath,
		in.HuntResult,
		in.Depth,
		in.MaxProvers,
		in.MaxConcurrentProvers,
	)
}

// RemediationPhase ports the `remediation_phase` reasoner
// (reasoners/phases.py:487).
func RemediationPhase(ctx context.Context, app appx.App, nodeID string, in RemediationPhaseInput) (map[string]any, error) {
	return phases.RemediationPhase(
		ctx, app, nodeID,
		in.RepoPath,
		in.VerifiedFindings,
		in.MaxConcurrentRemediations,
	)
}
