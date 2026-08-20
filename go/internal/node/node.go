// Package node is the SEC-AF wiring layer: it builds the shared *agent.Agent
// from the environment exactly as src/sec_af/app.py does at import time, mounts
// the 33-reasoner router (internal/reasoners) plus the externally driven
// `audit` reasoner, and serves them.
//
// The split mirrors the Python module:
//
//	node.go     app.py's Agent(...) constructor + main() (BuildAgent, Serve)
//	register.go app.include_router(reasoner_router) + @app.reasoner() audit
//	audit.go    the audit() body — the four `.call`s, checkpoints, error mapping
//	resolve.go  _resolve_repo
package node

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/orch"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// Node bundles the constructed agent with the resolved identity and the seams
// the audit handler is tested through.
type Node struct {
	// App is the SDK agent. It satisfies appx.App (Harness/AI/Note/Call)
	// directly, so the router handlers and the orchestrator both take it as-is,
	// and Serve mounts its handler.
	App *agent.Agent

	// NodeID is the resolved node id (NODE_ID env, or the sec-af default). It
	// names the node to the control plane and appears in log lines.
	NodeID string

	// callNodeID is the prefix the audit handler puts on its four `.call`
	// targets. app.py reads `NODE_ID = os.getenv("NODE_ID", "sec-af")` ONCE at
	// module import and interpolates it into every f-string, so the value is
	// captured here at build time rather than re-read per request.
	//
	// It is resolved with phases.NodeID() — the same reader internal/reasoners
	// uses for the `*_phase` targets — so the audit handler and the phase
	// reasoners can never disagree about which node they are calling. Both
	// phases.NodeID and envOr (used for NodeID above) treat an explicitly
	// empty NODE_ID as unset, so the registered identity and the `.call`
	// prefix are the SAME string for every possible value of the variable —
	// see phases.NodeID for why Go cannot reproduce Python's empty-string
	// spelling.
	callNodeID string

	// AgentFieldServer is the control-plane base URL the agent registers with.
	AgentFieldServer string

	// ListenAddress is the ":port" the SDK server binds (":"+PORT).
	ListenAddress string

	// auditApp is the agent-capability seam the audit handler makes its four
	// `.call`s and its notes through. It defaults to App; the handler tests
	// substitute an appx.Fake.
	auditApp appx.App

	// newOrchestrator constructs the audit orchestrator. Production points it at
	// orch.NewWithContext; the error-mapping tests inject a failing constructor
	// to exercise the path Python takes when AuditConfig.from_input raises.
	newOrchestrator func(ctx context.Context, app appx.App, in schemas.AuditInput) (*orch.AuditOrchestrator, error)

	// resolveRepo is the _resolve_repo seam. Production points it at
	// ResolveRepo; tests substitute a stub so no git subprocess runs.
	resolveRepo func(ctx context.Context, repoURL string) (string, error)

	// registered records every reasoner name passed through the single
	// registration path, in order, and tags records the tags each was
	// registered with (audit -> none; the 33 router reasoners ->
	// ["security","audit","red-team"]). The SDK exposes neither, so this is the
	// parity test's source of truth.
	registered []string
	tags       map[string][]string
}

// RegisteredNames returns a copy of the reasoner names registered on this node,
// in registration order.
func (n *Node) RegisteredNames() []string {
	return append([]string(nil), n.registered...)
}

// TagsFor returns a copy of the tags registered for name (nil when none).
func (n *Node) TagsFor(name string) []string {
	return append([]string(nil), n.tags[name]...)
}

// harnessConfig maps the resolved AI integration configuration onto the SDK
// harness configuration, porting app.py's
//
//	harness_config=HarnessConfig(
//	    provider=_ai_config.provider,
//	    model=_ai_config.harness_model,
//	    max_turns=_ai_config.max_turns,
//	    env=_ai_config.provider_env(),
//	    opencode_bin=_ai_config.opencode_bin,
//	    aforge_bin=_ai_config.aforge_bin,
//	    permission_mode="auto",
//	)
//
// The Python SDK takes a per-provider binary path (opencode_bin AND
// aforge_bin); the Go SDK takes ONE BinPath that applies to whichever provider
// is selected. So the value is chosen by provider: the aforge binary for
// provider "aforge", the opencode binary for provider "opencode", and empty
// for anything else — an empty BinPath lets the SDK pick the provider's own
// default executable, which is what Python does for the providers it has no
// explicit path for (claude-code, codex, gemini).
func harnessConfig(c config.AIIntegrationConfig, env map[string]string) *agent.HarnessConfig {
	return &agent.HarnessConfig{
		Provider:       c.Provider,
		Model:          c.HarnessModel,
		MaxTurns:       c.MaxTurns,
		PermissionMode: "auto",
		Env:            env,
		BinPath:        harnessBin(c),
	}
}

// harnessBin picks the single BinPath the Go SDK accepts. See harnessConfig.
func harnessBin(c config.AIIntegrationConfig) string {
	switch c.Provider {
	case "aforge":
		return c.AforgeBin
	case "opencode":
		return c.OpencodeBin
	default:
		return ""
	}
}

// BuildAgent constructs the SEC-AF agent from the environment, porting
// src/sec_af/app.py:35-58.
//
//	NODE_ID            default "sec-af"
//	AGENTFIELD_URL     control-plane URL, FALLING BACK to AGENTFIELD_SERVER,
//	                   then "http://localhost:8080". Note the precedence: this
//	                   repo reads AGENTFIELD_URL FIRST
//	                   (`os.getenv("AGENTFIELD_URL", os.getenv("AGENTFIELD_SERVER", ...))`),
//	                   which is the opposite of the SDK's own convention and of
//	                   pr-af. It is ported as written.
//	AGENTFIELD_API_KEY -> Config.Token (control-plane bearer)
//	PORT               default "8013" -> ListenAddress ":8013"
//	AGENT_CALLBACK_URL -> Config.PublicURL
//
// Two deliberate divergences from Python, both documented rather than "fixed":
//
//  1. CALLBACK URL. Python computes
//     `callback_url=os.getenv("AGENT_CALLBACK_URL", f"http://127.0.0.1:{os.getenv('PORT', '8004')}")`
//     while `main()` listens on `port=int(os.getenv("PORT", "8080"))`. The two
//     defaults DISAGREE: with neither PORT nor AGENT_CALLBACK_URL set, the
//     Python node listens on 8080 and tells the control plane to call it on
//     8004 — a latent bug, and one that cannot be "reproduced" usefully because
//     it makes the node unreachable. The Go port sets PublicURL from
//     AGENT_CALLBACK_URL when it is set and leaves it EMPTY otherwise, which
//     makes the SDK derive http://localhost:<actual listen port>. Every
//     deployment that sets AGENT_CALLBACK_URL (docker-compose, the Go compose
//     add-on) is byte-identical to Python; the unset case is merely correct
//     instead of broken.
//
//  2. AI CONFIG. Python always passes
//     `AIConfig(model=..., api_key=os.getenv("OPENROUTER_API_KEY", ""), api_base=...)`,
//     accepting an empty key. The Go SDK's ai.Config rejects an empty API key at
//     construction, so AIConfig is attached ONLY when OPENROUTER_API_KEY is set.
//     Construction then succeeds without a key (matching Python) and the `.ai()`
//     call fails at call time either way.
//
// A malformed numeric SEC_AF_* variable is an ERROR here, not a fallback:
// Python builds AIIntegrationConfig at module import, so the node fails to boot.
func BuildAgent(defaultNodeID, defaultPort, description string) (*Node, error) {
	nodeID := envOr("NODE_ID", defaultNodeID)
	server := envOr("AGENTFIELD_URL", envOr("AGENTFIELD_SERVER", "http://localhost:8080"))
	token := os.Getenv("AGENTFIELD_API_KEY")
	port := envOr("PORT", defaultPort)

	aiConf, err := config.AIConfigFromEnv()
	if err != nil {
		return nil, err
	}
	// provider_env() creates XDG_DATA_HOME eagerly; Python raises out of the
	// Agent constructor when that fails, so the node must not boot either.
	providerEnv, err := aiConf.ProviderEnv()
	if err != nil {
		return nil, err
	}

	cfg := agent.Config{
		NodeID:        nodeID,
		Version:       "0.1.0",
		AgentFieldURL: server,
		Token:         token,
		ListenAddress: ":" + port,
		PublicURL:     os.Getenv("AGENT_CALLBACK_URL"),
		CLIConfig:     &agent.CLIConfig{AppDescription: description},
		HarnessConfig: harnessConfig(aiConf, providerEnv),
	}
	if apiKey := os.Getenv("OPENROUTER_API_KEY"); apiKey != "" {
		cfg.AIConfig = &ai.Config{
			Model:   aiModelForAPI(aiConf.AIModel),
			APIKey:  apiKey,
			BaseURL: "https://openrouter.ai/api/v1",
		}
	}

	app, err := agent.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create agent %q: %w", nodeID, err)
	}

	return &Node{
		App:              app,
		NodeID:           nodeID,
		callNodeID:       phases.NodeID(),
		AgentFieldServer: server,
		ListenAddress:    ":" + port,
		auditApp:         app,
		newOrchestrator:  orch.NewWithContext,
		resolveRepo:      ResolveRepo,
		tags:             map[string][]string{},
	}, nil
}

// Serve starts the SDK's own HTTP server, registers the node with the control
// plane and blocks until the context is cancelled or SIGINT/SIGTERM arrives —
// the Go equivalent of app.py's `app.run(port=..., host="0.0.0.0")`.
//
// Unlike pr-af (which needs a bespoke mux for /webhook/github), SEC-AF adds NO
// custom route, so agent.Serve is used directly: it binds the listener BEFORE
// registering, which is what makes the control plane's post-registration health
// check succeed.
//
// Python parity, /health: app.py adds its own route returning
// `{"status": "healthy", "version": "0.1.0"}`. The Go SDK already serves
// /health, returning `{"status": "ok"}` — same 200, same purpose, different
// body. Every consumer in this repo is a liveness probe that only looks at the
// status code (the Dockerfile HEALTHCHECK's `curl -f`, the compose healthcheck,
// the manifest's `healthcheck: /health`), so the SDK's route is used as-is
// rather than shadowed. The SDK additionally serves /status, which is the
// endpoint the control plane's own health monitor polls.
func (n *Node) Serve(ctx context.Context) error {
	return n.App.Serve(ctx)
}

// envOr returns the value of key, or def when the env var is unset OR empty.
//
// Python parity: app.py's reads are `os.getenv(key, default)`, which returns ""
// for a key explicitly set to the empty string. Treating "" as unset here is
// the deliberate difference: an empty NODE_ID / PORT / AGENTFIELD_URL cannot
// produce a working node (agent.New would take an empty node id, and
// ListenAddress would be ":"), and docker-compose files routinely pass through
// empty values for unset variables. config.AIConfigFromEnv keeps the strict
// os.getenv semantics for the SEC_AF_* variables, where "" is meaningful.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// aiModelForAPI converts the configured AI model into the model ID the
// OpenRouter API expects.
//
// Python's `.ai()` path runs through LiteLLM, which CONSUMES a leading
// "openrouter/" as its routing prefix before calling the OpenRouter API. The Go
// SDK's ai client posts the model string verbatim to BaseURL, where
// "openrouter/minimax/minimax-m2.5" is an invalid model ID — so the routing
// prefix is stripped here to reach the same model Python does. The HARNESS
// model keeps its prefix (opencode's config wants the prefixed form, and
// docker-entrypoint.sh derives its provider model key by stripping it there).
func aiModelForAPI(model string) string {
	return strings.TrimPrefix(model, "openrouter/")
}
