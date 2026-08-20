// Package appx declares the agent-capability seam every reasoner and phase in
// the port depends on. Python code receives the SDK `Agent` (or the
// `AgentRouter` proxying to it) and calls `.harness(...)`, `.ai(...)`,
// `.note(...)` and `.call(...)` on it; the Go port receives an App. The live
// *agent.Agent satisfies App unchanged; tests supply fakes that record calls.
package appx

import (
	"context"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
	"github.com/Agent-Field/agentfield/sdk/go/ai"
	"github.com/Agent-Field/agentfield/sdk/go/harness"
)

// Harnesser is the `app.harness(...)` seam (sdk/go/agent/harness.go).
type Harnesser interface {
	Harness(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error)
}

// AIer is the `app.ai(...)` seam (sdk/go/agent/agent.go).
type AIer interface {
	AI(ctx context.Context, prompt string, opts ...ai.Option) (*ai.Response, error)
}

// Noter is the `app.note(msg, tags=[...])` seam.
type Noter interface {
	Note(ctx context.Context, message string, tags ...string)
}

// Caller is the `app.call(f"{NODE_ID}.x", **kwargs)` seam — the control-plane
// routed reasoner invocation that produces a tracked child execution (a DAG
// node). It returns the target reasoner's result map already unwrapped from
// the execution envelope on success, and an error on any failure status.
type Caller interface {
	Call(ctx context.Context, target string, input map[string]any) (map[string]any, error)
}

// App is the union the reasoners, phases and orchestrator are written
// against. *agent.Agent implements every method.
type App interface {
	Harnesser
	AIer
	Noter
	Caller
}

// Compile-time proof the live SDK agent satisfies the seam.
var _ App = (*agent.Agent)(nil)
