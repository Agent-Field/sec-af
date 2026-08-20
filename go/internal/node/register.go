package node

import (
	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/reasoners"
)

// register.go ports the two registration statements of src/sec_af/app.py:
//
//	@app.reasoner()
//	async def audit(...): ...        # the externally driven entry point
//	...
//	app.include_router(reasoner_router)   # the 33 router reasoners
//
// Python's decorator runs at import, BEFORE include_router at the bottom of the
// module, so `audit` is the first name on the node — the order is reproduced.

// RegisterAll registers the complete SEC-AF surface: `audit` on the agent
// itself, then the 33 router reasoners through internal/reasoners.RegisterAll.
//
// `audit` carries the input schema the live Python node publishes for it —
// reasoners.InputSchema replays the committed capture, exactly as the router
// registrations do — and NO tags (Python decorates it with @app.reasoner(), not
// on the tagged AgentRouter). The 33 router reasoners are mounted with
// agent.RouterOptions{Tags: reasoners.RouterTags}, which is the Go spelling of
// AgentRouter(tags=["security","audit","red-team"]): the SDK merges those tags
// into every handler the router carries. No Prefix — Python's include_router
// call passes none, so the reasoners keep their bare names and callers reach
// them as `<node_id>.<name>`.
func (n *Node) RegisterAll() {
	n.record(reasoners.NameAudit, nil)
	n.App.RegisterReasoner(reasoners.NameAudit, n.auditHandler,
		agent.WithInputSchema(reasoners.InputSchema(reasoners.NameAudit)))

	router := agent.NewRouter()
	for _, name := range reasoners.RegisterAll(router, n.App) {
		n.record(name, reasoners.RouterTags)
	}
	n.App.IncludeRouter(router, agent.RouterOptions{Tags: reasoners.RouterTags})
}

// record appends name (and its tags) to the node's registration bookkeeping —
// the source of truth for the parity test, since the SDK keeps its reasoner
// table unexported and reports an empty tag list on /discover.
func (n *Node) record(name string, tags []string) {
	if n.tags == nil {
		n.tags = map[string][]string{}
	}
	n.registered = append(n.registered, name)
	n.tags[name] = append([]string(nil), tags...)
}
