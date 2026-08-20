// Command sec-af is the Go SEC-AF security-audit node — the port of
// src/sec_af/app.py's module body plus main(). It builds the agent from the
// environment, registers the 34-reasoner surface (`audit` plus the 33 router
// reasoners of DESIGN.md §3) and serves it until SIGINT/SIGTERM.
//
// Defaults: NODE_ID "sec-af", PORT 8013. Both env vars override;
// docker-compose.go.yml sets NODE_ID=sec-af-go so the Go node can run beside
// the Python one against a single control plane.
//
// Boot environment:
//
//	AGENTFIELD_URL         control-plane base URL — checked FIRST in this repo
//	AGENTFIELD_SERVER      control-plane base URL fallback (default http://localhost:8080)
//	AGENTFIELD_API_KEY     control-plane bearer token
//	AGENT_CALLBACK_URL     base URL the CP uses to reach this node (else the SDK
//	                       derives http://localhost:<listen port>)
//	NODE_ID                node id (default sec-af)
//	PORT                   listen port (default 8013)
//	SEC_AF_PROVIDER        harness provider (falls back to HARNESS_PROVIDER, default aforge)
//	SEC_AF_MODEL           harness model (falls back to HARNESS_MODEL)
//	SEC_AF_AI_MODEL        model for .ai() calls (falls back to AI_MODEL, then SEC_AF_MODEL)
//	SEC_AF_AFORGE_BIN      aforge executable (falls back to AFORGE_BIN, default aforge)
//	SEC_AF_OPENCODE_BIN    opencode executable (default opencode)
//	SEC_AF_WORKSPACES_DIR  clone destination for remote repo URLs (default /workspaces)
//	SEC_AF_REPO_PATH       local checkout used when repo_url is neither a directory nor a URL
//	OPENROUTER_API_KEY     LLM key — required for the .ai() gates; AIConfig is
//	                       attached only when it is set (the SDK rejects an empty key)
package main

import (
	"context"
	"log"

	"github.com/Agent-Field/sec-af/go/internal/node"
)

func main() {
	n, err := node.BuildAgent(
		"sec-af",
		"8013",
		"AI-Native Security Analysis and Red-Teaming Agent",
	)
	if err != nil {
		log.Fatalf("sec-af: build agent: %v", err)
	}

	n.RegisterAll()

	if err := n.Serve(context.Background()); err != nil {
		log.Fatalf("sec-af: serve: %v", err)
	}
}
