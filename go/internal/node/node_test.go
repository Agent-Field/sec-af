package node

// Tests for BuildAgent and the node's registration surface.
//
// Validation contract (behaviour, derived from src/sec_af/app.py):
//
//   - NODE_ID / PORT / AGENTFIELD_API_KEY / AGENT_CALLBACK_URL are read from
//     the environment with app.py's defaults;
//   - the control-plane URL precedence in THIS repo is
//     AGENTFIELD_URL > AGENTFIELD_SERVER > http://localhost:8080;
//   - the harness configuration mirrors AIIntegrationConfig, with the ONE
//     binary path chosen by provider (aforge -> aforge_bin, opencode ->
//     opencode_bin, anything else -> empty so the SDK picks its own default);
//   - a malformed SEC_AF_* numeric variable fails the boot, as it does in
//     Python (the config is built at module import);
//   - the AI model loses its "openrouter/" LiteLLM routing prefix, and AIConfig
//     is attached only when OPENROUTER_API_KEY is set;
//   - the node registers `audit` first (untagged) and then the 33 router
//     reasoners, each tagged ["security","audit","red-team"].

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/reasoners"
)

// unsetEnv removes key for the duration of the test and restores it after.
//
// t.Setenv(key, "") is NOT equivalent: config.AIConfigFromEnv deliberately uses
// os.LookupEnv, so an EMPTY SEC_AF_MAX_TURNS is a parse error (Python's
// `int(os.getenv("SEC_AF_MAX_TURNS", "50"))` raises on "" too) while an ABSENT
// one yields the default. The tests below need "absent".
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
			return
		}
		_ = os.Unsetenv(key)
	})
}

// clearEnv removes every variable BuildAgent and config.AIConfigFromEnv read,
// so a test starts from the documented defaults regardless of the developer's
// shell.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"NODE_ID", "PORT", "AGENTFIELD_URL", "AGENTFIELD_SERVER", "AGENTFIELD_API_KEY",
		"AGENT_CALLBACK_URL", "OPENROUTER_API_KEY",
		"SEC_AF_PROVIDER", "HARNESS_PROVIDER", "SEC_AF_MODEL", "HARNESS_MODEL",
		"SEC_AF_AI_MODEL", "AI_MODEL", "SEC_AF_MAX_TURNS", "SEC_AF_AI_MAX_RETRIES",
		"SEC_AF_AI_INITIAL_BACKOFF_SECONDS", "SEC_AF_AI_MAX_BACKOFF_SECONDS",
		"SEC_AF_OPENCODE_BIN", "SEC_AF_AFORGE_BIN", "AFORGE_BIN",
		"SEC_AF_OPENCODE_SERVER", "OPENCODE_SERVER",
	} {
		unsetEnv(t, key)
	}
	// XDG_DATA_HOME is created by provider_env(); point it at a scratch dir so
	// the test never writes into the developer's real data home or /tmp.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
}

func newTestNode(t *testing.T) *Node {
	t.Helper()
	n, err := BuildAgent("sec-af", "8013", "AI-Native Security Analysis and Red-Teaming Agent")
	if err != nil {
		t.Fatalf("BuildAgent: %v", err)
	}
	return n
}

func TestBuildAgentDefaults(t *testing.T) {
	clearEnv(t)

	n := newTestNode(t)

	if n.NodeID != "sec-af" {
		t.Errorf("NodeID = %q, want sec-af", n.NodeID)
	}
	if n.ListenAddress != ":8013" {
		t.Errorf("ListenAddress = %q, want :8013", n.ListenAddress)
	}
	if n.AgentFieldServer != "http://localhost:8080" {
		t.Errorf("AgentFieldServer = %q, want http://localhost:8080", n.AgentFieldServer)
	}
	if n.App == nil {
		t.Fatal("App is nil")
	}
}

func TestBuildAgentEnvOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("NODE_ID", "sec-af-go")
	t.Setenv("PORT", "9999")
	t.Setenv("AGENTFIELD_SERVER", "http://cp:8080")
	t.Setenv("AGENTFIELD_API_KEY", "tok")

	n := newTestNode(t)

	if n.NodeID != "sec-af-go" {
		t.Errorf("NodeID = %q, want sec-af-go", n.NodeID)
	}
	if n.ListenAddress != ":9999" {
		t.Errorf("ListenAddress = %q, want :9999", n.ListenAddress)
	}
	if n.AgentFieldServer != "http://cp:8080" {
		t.Errorf("AgentFieldServer = %q, want http://cp:8080", n.AgentFieldServer)
	}
}

// TestBuildAgentURLPrecedence pins the quirk of THIS repo: app.py reads
// AGENTFIELD_URL first and only then AGENTFIELD_SERVER — the reverse of the
// SDK's own convention and of pr-af.
func TestBuildAgentURLPrecedence(t *testing.T) {
	clearEnv(t)
	t.Setenv("AGENTFIELD_URL", "http://from-url:8080")
	t.Setenv("AGENTFIELD_SERVER", "http://from-server:8080")

	if got := newTestNode(t).AgentFieldServer; got != "http://from-url:8080" {
		t.Errorf("AgentFieldServer = %q, want AGENTFIELD_URL to win", got)
	}
}

// TestBuildAgentMalformedNumberFailsBoot: Python builds AIIntegrationConfig at
// import, so `SEC_AF_MAX_TURNS=abc` crashes the process before it can serve.
func TestBuildAgentMalformedNumberFailsBoot(t *testing.T) {
	clearEnv(t)
	t.Setenv("SEC_AF_MAX_TURNS", "abc")

	if _, err := BuildAgent("sec-af", "8013", "d"); err == nil {
		t.Fatal("want BuildAgent to fail on a malformed SEC_AF_MAX_TURNS")
	}
}

func TestHarnessBinByProvider(t *testing.T) {
	clearEnv(t)

	cases := []struct {
		provider string
		aforge   string
		opencode string
		want     string
	}{
		{"aforge", "/usr/local/bin/aforge", "opencode", "/usr/local/bin/aforge"},
		{"opencode", "aforge", "/home/secaf/.opencode/bin/opencode", "/home/secaf/.opencode/bin/opencode"},
		// Every other provider gets an empty BinPath so the SDK resolves its own
		// default executable — the Python SDK is told nothing for these either.
		{"claude-code", "aforge", "opencode", ""},
		{"codex", "aforge", "opencode", ""},
		{"gemini", "aforge", "opencode", ""},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			t.Setenv("SEC_AF_PROVIDER", tc.provider)
			t.Setenv("SEC_AF_AFORGE_BIN", tc.aforge)
			t.Setenv("SEC_AF_OPENCODE_BIN", tc.opencode)

			// Boot the node so the environment is proven to be accepted, then
			// read the same resolved config back to check the BinPath choice.
			newTestNode(t)

			cfg, err := config.AIConfigFromEnv()
			if err != nil {
				t.Fatalf("AIConfigFromEnv: %v", err)
			}
			hc := harnessConfig(cfg, nil)
			if hc.BinPath != tc.want {
				t.Errorf("BinPath = %q, want %q", hc.BinPath, tc.want)
			}
			if hc.Provider != tc.provider {
				t.Errorf("Provider = %q, want %q", hc.Provider, tc.provider)
			}
			if hc.PermissionMode != "auto" {
				t.Errorf("PermissionMode = %q, want auto", hc.PermissionMode)
			}
			if hc.MaxTurns != 50 {
				t.Errorf("MaxTurns = %d, want the SEC_AF_MAX_TURNS default 50", hc.MaxTurns)
			}
		})
	}
}

func TestAIModelForAPIStripsRoutingPrefix(t *testing.T) {
	cases := map[string]string{
		"openrouter/minimax/minimax-m2.5": "minimax/minimax-m2.5",
		"minimax/minimax-m2.5":            "minimax/minimax-m2.5",
		"":                                "",
		// Only a LEADING prefix is stripped, and only one.
		"openrouter/openrouter/x": "openrouter/x",
	}
	for in, want := range cases {
		if got := aiModelForAPI(in); got != want {
			t.Errorf("aiModelForAPI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnvOrTreatsEmptyAsUnset(t *testing.T) {
	t.Setenv("SEC_AF_TEST_ENV_OR", "")
	if got := envOr("SEC_AF_TEST_ENV_OR", "fallback"); got != "fallback" {
		t.Errorf("envOr with an empty value = %q, want the fallback", got)
	}
	t.Setenv("SEC_AF_TEST_ENV_OR", "value")
	if got := envOr("SEC_AF_TEST_ENV_OR", "fallback"); got != "value" {
		t.Errorf("envOr = %q, want value", got)
	}
}

// pythonSurface is the independent parity checklist for the FULL node surface:
// `audit` (registered by @app.reasoner() at the top of app.py) followed by the
// 33 router reasoners in DESIGN.md §3 order.
var pythonSurface = append([]string{reasoners.NameAudit}, reasoners.Names...)

func TestNodeRegisterAllExactSurface(t *testing.T) {
	clearEnv(t)
	n := newTestNode(t)
	n.RegisterAll()

	got := n.RegisteredNames()
	if !reflect.DeepEqual(got, pythonSurface) {
		t.Fatalf("registered surface mismatch:\n got  = %v\n want = %v", got, pythonSurface)
	}
	if len(got) != 34 {
		t.Errorf("surface size = %d, want 34 (audit + 33 router reasoners)", len(got))
	}

	seen := map[string]int{}
	for _, name := range got {
		seen[name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("reasoner %q registered %d times (collision)", name, count)
		}
	}

	if tags := n.TagsFor(reasoners.NameAudit); len(tags) != 0 {
		t.Errorf("audit tags = %v, want none (it is not on the tagged router)", tags)
	}
	for _, name := range reasoners.Names {
		if tags := n.TagsFor(name); !reflect.DeepEqual(tags, []string{"security", "audit", "red-team"}) {
			t.Errorf("%s tags = %v, want [security audit red-team]", name, tags)
		}
	}
}

// TestBuildAgentCapturesCallNodeID pins that the `.call` prefix is read ONCE at
// build time (Python's module-level NODE_ID) and agrees with the id the node
// registers under.
func TestBuildAgentCapturesCallNodeID(t *testing.T) {
	clearEnv(t)
	t.Setenv("NODE_ID", "sec-af-go")

	n := newTestNode(t)
	if n.callNodeID != "sec-af-go" {
		t.Errorf("callNodeID = %q, want sec-af-go", n.callNodeID)
	}
	if n.callNodeID != n.NodeID {
		t.Errorf("callNodeID %q and NodeID %q disagree", n.callNodeID, n.NodeID)
	}

	// Changing the environment after the build must NOT move the targets.
	t.Setenv("NODE_ID", "someone-else")
	if n.callNodeID != "sec-af-go" {
		t.Errorf("callNodeID changed after boot: %q", n.callNodeID)
	}
}

// TestBuildAgentEmptyNodeIDKeepsTheTwoReadersInSync is the case an explicitly
// empty variable (`NODE_ID=`, e.g. a docker-compose `NODE_ID=${NODE_ID}`
// passthrough) used to break: BuildAgent resolved the registered id with envOr
// ("" -> "sec-af") while the `.call` prefix came from os.LookupEnv ("" -> ""),
// so the node registered as "sec-af" and then emitted DAG edges targeting
// ".recon_phase". Python cannot get into that state — app.py:32 and
// reasoners/phases.py:31 read the SAME `os.getenv("NODE_ID", "sec-af")`, so its
// two values are always the identical string.
func TestBuildAgentEmptyNodeIDKeepsTheTwoReadersInSync(t *testing.T) {
	clearEnv(t)
	t.Setenv("NODE_ID", "")

	n := newTestNode(t)
	if n.callNodeID != n.NodeID {
		t.Errorf("callNodeID %q and NodeID %q disagree", n.callNodeID, n.NodeID)
	}
	if n.NodeID != "sec-af" {
		t.Errorf("NodeID = %q, want the sec-af default", n.NodeID)
	}
	if got := phases.NodeID(); got != n.NodeID {
		t.Errorf("phases.NodeID() = %q, want %q", got, n.NodeID)
	}
}

// TestNodeInputSchemasMatchThePythonNode covers the whole 34-reasoner surface
// at the place it actually exists — the built node — and reads the schemas back
// out of the SDK through /discover, the same payload the control plane is given
// at registration.
//
// Validation contract: no reasoner may be published on the Go SDK's
// `{"type":"object","additionalProperties":true}` placeholder, and every one of
// them must carry the schema the Python node publishes for that id (see
// internal/reasoners/input_schemas.go for the capture and how to regenerate it).
func TestNodeInputSchemasMatchThePythonNode(t *testing.T) {
	clearEnv(t)
	n := newTestNode(t)
	n.RegisterAll()

	published := discoverInputSchemas(t, n)

	if len(published) != 34 {
		t.Fatalf("/discover reports %d reasoners, want 34", len(published))
	}

	placeholder := decodeJSON(t, []byte(`{"type":"object","additionalProperties":true}`))
	for _, name := range n.RegisteredNames() {
		got, ok := published[name]
		if !ok {
			t.Errorf("%s: not present in /discover", name)
			continue
		}
		want := decodeJSON(t, reasoners.InputSchema(name))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: published schema mismatch\n got  = %#v\n want = %#v", name, got, want)
		}
		if reflect.DeepEqual(got, placeholder) {
			t.Errorf("%s: published the SDK placeholder schema", name)
		}
	}
}

// TestAuditInputSchemaMatchesThePythonSignature transcribes the audit()
// signature (app.py:121-141) independently of the capture, so a bad
// regeneration fails here too.
//
// It is the schema with the most of Python's derivation quirks in one place:
// ELEVEN parameters are PEP 604 optionals (`str | None`, `list[str] | None`,
// `float | None`, `int | None`) and every one of them is published as a bare
// {"type":"object"} rather than as its base type or an array — the Union branch
// of Agent._type_to_json_schema only fires for typing.Union, and a `X | None`
// annotation is a types.UnionType with no __origin__. Only `repo_url` is
// required; the other nineteen parameters all have defaults.
func TestAuditInputSchemaMatchesThePythonSignature(t *testing.T) {
	want := decodeJSON(t, []byte(`{"type":"object","properties":{
		"repo_url":{"type":"string"},
		"depth":{"type":"string"},
		"branch":{"type":"string"},
		"commit_sha":{"type":"object"},
		"base_commit_sha":{"type":"object"},
		"severity_threshold":{"type":"string"},
		"scan_types":{"type":"object"},
		"output_formats":{"type":"object"},
		"compliance_frameworks":{"type":"object"},
		"max_cost_usd":{"type":"object"},
		"max_provers":{"type":"object"},
		"max_duration_seconds":{"type":"object"},
		"include_paths":{"type":"object"},
		"exclude_paths":{"type":"object"},
		"is_pr":{"type":"boolean"},
		"pr_id":{"type":"object"},
		"post_pr_comments":{"type":"boolean"},
		"fail_on_findings":{"type":"boolean"},
		"enable_dast":{"type":"boolean"},
		"resume_from_checkpoint":{"type":"object"}},
		"required":["repo_url"]}`))

	if got := decodeJSON(t, reasoners.InputSchema(reasoners.NameAudit)); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit schema mismatch\n got  = %#v\n want = %#v", got, want)
	}

	clearEnv(t)
	n := newTestNode(t)
	n.RegisterAll()

	if got := discoverInputSchemas(t, n)[reasoners.NameAudit]; !reflect.DeepEqual(got, want) {
		t.Fatalf("published audit schema mismatch\n got  = %#v\n want = %#v", got, want)
	}
}

// discoverInputSchemas asks the node's own agent which reasoners it holds and
// with which input schemas — the SDK keeps its reasoner table unexported, so
// /discover is the only read-back, and it is the registration payload itself.
func discoverInputSchemas(t *testing.T, n *Node) map[string]any {
	t.Helper()

	rec := httptest.NewRecorder()
	n.App.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/discover status = %d, want 200", rec.Code)
	}

	var payload struct {
		Reasoners []struct {
			ID          string `json:"id"`
			InputSchema any    `json:"input_schema"`
		} `json:"reasoners"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /discover: %v", err)
	}

	out := make(map[string]any, len(payload.Reasoners))
	for _, r := range payload.Reasoners {
		out[r.ID] = r.InputSchema
	}
	return out
}

// decodeJSON renders raw JSON as untyped Go values so comparisons ignore object
// key order while still pinning array order (`required` follows the Python
// parameter order).
func decodeJSON(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

// TestServeFailsWhenTheControlPlaneIsUnreachable pins the fourth deliberate
// divergence listed in go/README.md's "Parity notes", so the documentation
// cannot silently stop describing the binary.
//
// Validation contract (behaviour):
//
//   - the Python node DEGRADES: agent_server.py installs a ConnectionManager
//     whose start() is non-blocking; on failure connection_manager.py logs
//     "AgentField server unavailable - running in degraded mode", keeps serving,
//     and retries every 10s;
//   - the Go SDK has no such retry — client.RegisterNode returns the error,
//     Agent.Serve propagates it, and cmd/sec-af/main.go log.Fatalf's on it — so
//     the process EXITS instead.
//
// This is SDK-level behaviour, not something the port chose, and it is why the
// compose add-on restart-loops until the Python stack's control plane answers.
// The test exists to pin the divergence as REAL: if a future SDK gains the
// Python retry semantics, Serve stops returning here and the README bullet has
// to be revisited rather than quietly rotting.
func TestServeFailsWhenTheControlPlaneIsUnreachable(t *testing.T) {
	clearEnv(t)

	// A port nothing is listening on: bind, read the address, close. The
	// connection is then REFUSED immediately rather than timing out.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	dead := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}

	t.Setenv("AGENTFIELD_SERVER", "http://"+dead)
	t.Setenv("PORT", "0") // ephemeral listen port, so the test never collides
	n := newTestNode(t)
	// Register the surface first: an agent with no reasoners fails Initialize
	// for a DIFFERENT reason ("no reasoners or skills registered"), which would
	// make this test pass without ever reaching the control-plane call.
	n.RegisterAll()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := n.Serve(ctx); err == nil {
		t.Fatal("Serve returned nil with the control plane down; the Go node is " +
			"documented to FAIL here where the Python node degrades and retries")
	} else if !strings.Contains(err.Error(), "register node") {
		t.Errorf("Serve error = %v, want the `register node` failure from client.RegisterNode", err)
	}
}
