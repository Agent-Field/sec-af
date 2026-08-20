package config

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
)

// This file ports the config-related tests from tests/test_config.py. Each Go
// test names the Python test it derives from so reviewers can diff coverage.

// unsetEnv removes keys for the duration of the test and restores whatever was
// there afterwards — the Go equivalent of monkeypatch.delenv(..., raising=False).
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		key := key
		if old, had := os.LookupEnv(key); had {
			t.Cleanup(func() { _ = os.Setenv(key, old) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(key) })
		}
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}

func approx(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("got %v, want ~%v", got, want)
	}
}

func ptrF(f float64) *float64 { return &f }
func ptrI(i int) *int         { return &i }

// sampleAuditInput mirrors tests/conftest.py::sample_audit_input.
func sampleAuditInput() AuditInputFields {
	return AuditInputFields{
		Depth:                "standard",
		SeverityThreshold:    "low",
		ScanTypes:            []string{"sast", "secrets", "config"},
		OutputFormats:        []string{"json", "sarif", "markdown"},
		ComplianceFrameworks: []string{"PCI-DSS", "SOC2", "OWASP"},
		IncludePaths:         []string{"src/"},
		ExcludePaths:         []string{"tests/", "vendor/", ".git/"},
		MaxCostUSD:           ptrF(10.0),
		MaxProvers:           ptrI(4),
		MaxDurationSeconds:   ptrI(900),
	}
}

// TestDepthProfileValuesAreStable ports
// test_config.py::test_depth_profile_values_are_stable.
func TestDepthProfileValuesAreStable(t *testing.T) {
	if DepthQuick != "quick" {
		t.Errorf("DepthQuick = %q", DepthQuick)
	}
	if DepthStandard != "standard" {
		t.Errorf("DepthStandard = %q", DepthStandard)
	}
	if DepthThorough != "thorough" {
		t.Errorf("DepthThorough = %q", DepthThorough)
	}
}

// TestBudgetConfigDefaultsSumTo100Percent ports
// test_config.py::test_budget_config_defaults_sum_to_100_percent.
func TestBudgetConfigDefaultsSumTo100Percent(t *testing.T) {
	b := DefaultBudgetConfig()
	approx(t, b.ReconBudgetPct+b.HuntBudgetPct+b.ProveBudgetPct, 1.0)
	if b.MaxCostUSD != nil || b.MaxProvers != nil || b.MaxDurationSeconds != nil {
		t.Errorf("caps default to non-None: %#v", b)
	}
	// The remaining pydantic defaults, which the Python test does not cover but
	// the phases depend on.
	if b.MaxConcurrentHunters != 4 || b.MaxConcurrentProvers != 3 || b.HunterEarlyStopFileThreshold != 30 {
		t.Errorf("concurrency/threshold defaults = %#v", b)
	}
}

// TestAuditConfigFromInputMapsFieldsAndBudget ports
// test_config.py::test_audit_config_from_input_maps_fields_and_budget.
func TestAuditConfigFromInputMapsFieldsAndBudget(t *testing.T) {
	cfg, err := AuditConfig{}.FromInputFields(sampleAuditInput(), "/tmp/sec-af-repo")
	if err != nil {
		t.Fatalf("FromInputFields: %v", err)
	}
	if cfg.RepoPath != "/tmp/sec-af-repo" {
		t.Errorf("RepoPath = %q", cfg.RepoPath)
	}
	if cfg.Depth != DepthStandard {
		t.Errorf("Depth = %q", cfg.Depth)
	}
	if !reflect.DeepEqual(cfg.ScanTypes, []string{"sast", "secrets", "config"}) {
		t.Errorf("ScanTypes = %#v", cfg.ScanTypes)
	}
	if !reflect.DeepEqual(cfg.OutputFormats, []string{"json", "sarif", "markdown"}) {
		t.Errorf("OutputFormats = %#v", cfg.OutputFormats)
	}
	if cfg.Budget.MaxCostUSD == nil || *cfg.Budget.MaxCostUSD != 10.0 {
		t.Errorf("Budget.MaxCostUSD = %#v", cfg.Budget.MaxCostUSD)
	}
	if cfg.Budget.MaxProvers == nil || *cfg.Budget.MaxProvers != 4 {
		t.Errorf("Budget.MaxProvers = %#v", cfg.Budget.MaxProvers)
	}
	if cfg.Budget.MaxDurationSeconds == nil || *cfg.Budget.MaxDurationSeconds != 900 {
		t.Errorf("Budget.MaxDurationSeconds = %#v", cfg.Budget.MaxDurationSeconds)
	}
	// BudgetConfig(...) is constructed with only the three caps, so everything
	// else keeps its own default.
	if cfg.Budget.MaxConcurrentHunters != 4 || cfg.Budget.MaxConcurrentProvers != 3 {
		t.Errorf("budget concurrency lost its defaults: %#v", cfg.Budget)
	}
	approx(t, cfg.Budget.ReconBudgetPct, 0.10)
	// Fields from_input does not pass keep their pydantic defaults.
	if cfg.SeverityThreshold != "low" {
		t.Errorf("SeverityThreshold = %q", cfg.SeverityThreshold)
	}
	if !reflect.DeepEqual(cfg.IncludePaths, []string{"src/"}) {
		t.Errorf("IncludePaths = %#v", cfg.IncludePaths)
	}
	if !reflect.DeepEqual(cfg.ExcludePaths, []string{"tests/", "vendor/", ".git/"}) {
		t.Errorf("ExcludePaths = %#v", cfg.ExcludePaths)
	}
	if !reflect.DeepEqual(cfg.ComplianceFrameworks, []string{"PCI-DSS", "SOC2", "OWASP"}) {
		t.Errorf("ComplianceFrameworks = %#v", cfg.ComplianceFrameworks)
	}
}

// TestAuditConfigRejectsInvalidDepth ports
// test_config.py::test_audit_config_rejects_invalid_depth — from_input uses the
// STRICT enum constructor, so an unknown depth fails rather than falling back to
// STANDARD the way _normalize_depth would.
func TestAuditConfigRejectsInvalidDepth(t *testing.T) {
	in := sampleAuditInput()
	in.Depth = "invalid"
	_, err := AuditConfig{}.FromInputFields(in, "/tmp/sec-af-repo")
	if err == nil {
		t.Fatal("FromInputFields accepted an invalid depth")
	}
	if want := "'invalid' is not a valid DepthProfile"; err.Error() != want {
		t.Errorf("error = %q, python ValueError = %q", err.Error(), want)
	}
}

// TestAuditConfigDefaultsToAforgeProvider ports
// test_config.py::test_audit_config_defaults_to_aforge_provider.
func TestAuditConfigDefaultsToAforgeProvider(t *testing.T) {
	cfg, err := AuditConfig{}.FromInputFields(sampleAuditInput(), "/tmp/sec-af-repo")
	if err != nil {
		t.Fatalf("FromInputFields: %v", err)
	}
	if cfg.Provider != "aforge" {
		t.Errorf("Provider = %q, want aforge", cfg.Provider)
	}
}

// TestFromInputProjectsAnAuditInputShapedValue covers the `in any` projection
// path — the one the node package will use with schemas.AuditInput.
func TestFromInputProjectsAnAuditInputShapedValue(t *testing.T) {
	// Deliberately a DIFFERENT struct with extra fields, standing in for
	// schemas.AuditInput.
	type auditInputLike struct {
		RepoURL              string   `json:"repo_url"`
		Branch               string   `json:"branch"`
		Depth                string   `json:"depth"`
		SeverityThreshold    string   `json:"severity_threshold"`
		ScanTypes            []string `json:"scan_types"`
		OutputFormats        []string `json:"output_formats"`
		ComplianceFrameworks []string `json:"compliance_frameworks"`
		IncludePaths         []string `json:"include_paths"`
		ExcludePaths         []string `json:"exclude_paths"`
		MaxCostUSD           *float64 `json:"max_cost_usd"`
		MaxProvers           *int     `json:"max_provers"`
		MaxDurationSeconds   *int     `json:"max_duration_seconds"`
		IsPR                 bool     `json:"is_pr"`
	}
	in := auditInputLike{
		RepoURL:           "https://github.com/Agent-Field/sec-af",
		Branch:            "main",
		Depth:             "thorough",
		SeverityThreshold: "high",
		ScanTypes:         []string{"sast"},
		OutputFormats:     []string{"json"},
		MaxCostUSD:        ptrF(2.5),
		IsPR:              true,
	}
	cfg, err := AuditConfig{}.FromInput(in, "/repo")
	if err != nil {
		t.Fatalf("FromInput: %v", err)
	}
	if cfg.Depth != DepthThorough {
		t.Errorf("Depth = %q", cfg.Depth)
	}
	if cfg.SeverityThreshold != "high" {
		t.Errorf("SeverityThreshold = %q", cfg.SeverityThreshold)
	}
	if cfg.Budget.MaxCostUSD == nil || *cfg.Budget.MaxCostUSD != 2.5 {
		t.Errorf("Budget.MaxCostUSD = %#v", cfg.Budget.MaxCostUSD)
	}
	if cfg.RepoPath != "/repo" {
		t.Errorf("RepoPath = %q", cfg.RepoPath)
	}
}

// TestNormalizeDepth covers the lenient in-pipeline helper (phases.py:52 and its
// three verbatim copies): case-insensitive, and ANY unknown value becomes
// STANDARD.
func TestNormalizeDepth(t *testing.T) {
	cases := []struct {
		in   string
		want DepthProfile
	}{
		{"quick", DepthQuick},
		{"standard", DepthStandard},
		{"thorough", DepthThorough},
		{"QUICK", DepthQuick},
		{"Thorough", DepthThorough},
		{"invalid", DepthStandard},
		{"", DepthStandard},
		{"deep", DepthStandard},
		{" quick", DepthStandard}, // python: DepthProfile(" quick") raises -> STANDARD
	}
	for _, c := range cases {
		if got := NormalizeDepth(c.in); got != c.want {
			t.Errorf("NormalizeDepth(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// The business_logic.py `str | DepthProfile` variant: an already-typed
	// profile round-trips unchanged.
	if got := NormalizeDepth(string(DepthThorough)); got != DepthThorough {
		t.Errorf("NormalizeDepth(DepthThorough) = %q", got)
	}
}

// TestAIIntegrationConfigUsesSecAfEnvPrecedence ports
// test_config.py::test_ai_integration_config_uses_sec_af_env_precedence.
func TestAIIntegrationConfigUsesSecAfEnvPrecedence(t *testing.T) {
	t.Setenv("SEC_AF_PROVIDER", "custom-provider")
	t.Setenv("HARNESS_PROVIDER", "fallback-provider")
	t.Setenv("SEC_AF_MODEL", "provider/model-a")
	t.Setenv("HARNESS_MODEL", "provider/model-b")
	t.Setenv("SEC_AF_AI_MODEL", "provider/model-c")
	t.Setenv("SEC_AF_MAX_TURNS", "75")
	t.Setenv("SEC_AF_AI_MAX_RETRIES", "6")
	t.Setenv("SEC_AF_AI_INITIAL_BACKOFF_SECONDS", "1.5")
	t.Setenv("SEC_AF_AI_MAX_BACKOFF_SECONDS", "12")
	t.Setenv("SEC_AF_OPENCODE_BIN", "/usr/local/bin/opencode")
	t.Setenv("SEC_AF_AFORGE_BIN", "/usr/local/bin/aforge")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.Provider != "custom-provider" {
		t.Errorf("Provider = %q", cfg.Provider)
	}
	if cfg.HarnessModel != "provider/model-a" {
		t.Errorf("HarnessModel = %q", cfg.HarnessModel)
	}
	if cfg.AIModel != "provider/model-c" {
		t.Errorf("AIModel = %q", cfg.AIModel)
	}
	if cfg.MaxTurns != 75 {
		t.Errorf("MaxTurns = %d", cfg.MaxTurns)
	}
	if cfg.MaxRetries != 6 {
		t.Errorf("MaxRetries = %d", cfg.MaxRetries)
	}
	approx(t, cfg.InitialBackoffSeconds, 1.5)
	approx(t, cfg.MaxBackoffSeconds, 12)
	if cfg.OpencodeBin != "/usr/local/bin/opencode" {
		t.Errorf("OpencodeBin = %q", cfg.OpencodeBin)
	}
	if cfg.AforgeBin != "/usr/local/bin/aforge" {
		t.Errorf("AforgeBin = %q", cfg.AforgeBin)
	}
}

// TestAIIntegrationConfigFallsBackToHarnessAndDefaults ports
// test_config.py::test_ai_integration_config_falls_back_to_harness_and_defaults.
func TestAIIntegrationConfigFallsBackToHarnessAndDefaults(t *testing.T) {
	unsetEnv(t,
		"SEC_AF_PROVIDER", "HARNESS_PROVIDER",
		"SEC_AF_MODEL", "HARNESS_MODEL",
		"SEC_AF_AI_MODEL", "AI_MODEL",
		"SEC_AF_MAX_TURNS", "SEC_AF_AI_MAX_RETRIES",
		"SEC_AF_AI_INITIAL_BACKOFF_SECONDS", "SEC_AF_AI_MAX_BACKOFF_SECONDS",
		"SEC_AF_OPENCODE_BIN", "SEC_AF_AFORGE_BIN", "AFORGE_BIN",
	)

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.Provider != "aforge" {
		t.Errorf("Provider = %q", cfg.Provider)
	}
	if cfg.HarnessModel != "minimax/minimax-m2.5" {
		t.Errorf("HarnessModel = %q", cfg.HarnessModel)
	}
	if cfg.AIModel != "minimax/minimax-m2.5" {
		t.Errorf("AIModel = %q", cfg.AIModel)
	}
	if cfg.MaxTurns != 50 {
		t.Errorf("MaxTurns = %d", cfg.MaxTurns)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d", cfg.MaxRetries)
	}
	approx(t, cfg.InitialBackoffSeconds, 2.0)
	approx(t, cfg.MaxBackoffSeconds, 8.0)
	if cfg.OpencodeBin != "opencode" {
		t.Errorf("OpencodeBin = %q", cfg.OpencodeBin)
	}
	if cfg.AforgeBin != "aforge" {
		t.Errorf("AforgeBin = %q", cfg.AforgeBin)
	}

	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	if env["AGENTFIELD_AFORGE_COMMAND"] != "exec" {
		t.Errorf("AGENTFIELD_AFORGE_COMMAND = %q, want exec", env["AGENTFIELD_AFORGE_COMMAND"])
	}
}

// TestAIIntegrationConfigFallbackChains covers the per-variable fallbacks the
// Python test only exercises at their endpoints.
func TestAIIntegrationConfigFallbackChains(t *testing.T) {
	unsetEnv(t,
		"SEC_AF_PROVIDER", "SEC_AF_MODEL", "SEC_AF_AI_MODEL", "AI_MODEL",
		"SEC_AF_AFORGE_BIN", "SEC_AF_OPENCODE_SERVER", "OPENCODE_SERVER",
	)
	t.Setenv("HARNESS_PROVIDER", "opencode")
	t.Setenv("HARNESS_MODEL", "provider/harness-model")
	t.Setenv("AFORGE_BIN", "/opt/aforge")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.Provider != "opencode" {
		t.Errorf("Provider = %q, want the HARNESS_PROVIDER fallback", cfg.Provider)
	}
	if cfg.HarnessModel != "provider/harness-model" {
		t.Errorf("HarnessModel = %q, want the HARNESS_MODEL fallback", cfg.HarnessModel)
	}
	// ai_model falls back SEC_AF_AI_MODEL > AI_MODEL > SEC_AF_MODEL > default.
	// HARNESS_MODEL is NOT in that chain, so the code default wins here.
	if cfg.AIModel != "minimax/minimax-m2.5" {
		t.Errorf("AIModel = %q — HARNESS_MODEL must not leak into the ai_model chain", cfg.AIModel)
	}
	if cfg.AforgeBin != "/opt/aforge" {
		t.Errorf("AforgeBin = %q, want the AFORGE_BIN fallback", cfg.AforgeBin)
	}
	if cfg.OpencodeServer != nil {
		t.Errorf("OpencodeServer = %v, want nil when neither key is set", *cfg.OpencodeServer)
	}

	// ai_model's third rung: SEC_AF_MODEL.
	t.Setenv("SEC_AF_MODEL", "provider/sec-af-model")
	cfg, err = AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.AIModel != "provider/sec-af-model" {
		t.Errorf("AIModel = %q, want the SEC_AF_MODEL fallback", cfg.AIModel)
	}
}

// TestAIIntegrationConfigEmptyStringWins pins the os.getenv semantic Go's
// os.Getenv cannot express: an env var SET TO THE EMPTY STRING is a value, not
// an absent key, so it beats the fallback.
func TestAIIntegrationConfigEmptyStringWins(t *testing.T) {
	unsetEnv(t, "OPENCODE_SERVER")
	t.Setenv("SEC_AF_PROVIDER", "")
	t.Setenv("HARNESS_PROVIDER", "aforge")
	t.Setenv("SEC_AF_OPENCODE_SERVER", "")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.Provider != "" {
		t.Errorf("Provider = %q, want \"\" (python os.getenv returns the empty value)", cfg.Provider)
	}
	if cfg.OpencodeServer == nil || *cfg.OpencodeServer != "" {
		t.Errorf("OpencodeServer = %#v, want a pointer to \"\" (set-but-empty is not None)", cfg.OpencodeServer)
	}
}

// TestAIIntegrationConfigOpencodeServerFallback: SEC_AF_OPENCODE_SERVER >
// OPENCODE_SERVER > None.
func TestAIIntegrationConfigOpencodeServerFallback(t *testing.T) {
	unsetEnv(t, "SEC_AF_OPENCODE_SERVER")
	t.Setenv("OPENCODE_SERVER", "http://localhost:4096")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.OpencodeServer == nil || *cfg.OpencodeServer != "http://localhost:4096" {
		t.Errorf("OpencodeServer = %#v", cfg.OpencodeServer)
	}
}

// TestAIIntegrationConfigMalformedNumbersAreFatal: Python's int()/float() raises
// inside the default_factory, which runs at app.py import — the node fails to
// boot rather than silently using a default.
func TestAIIntegrationConfigMalformedNumbersAreFatal(t *testing.T) {
	for _, c := range []struct{ key, value string }{
		{"SEC_AF_MAX_TURNS", "fifty"},
		{"SEC_AF_MAX_TURNS", ""},
		{"SEC_AF_MAX_TURNS", "50.5"},
		{"SEC_AF_AI_MAX_RETRIES", "many"},
		{"SEC_AF_AI_INITIAL_BACKOFF_SECONDS", "slow"},
		{"SEC_AF_AI_MAX_BACKOFF_SECONDS", "8s"},
	} {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			t.Setenv(c.key, c.value)
			if _, err := AIConfigFromEnv(); err == nil {
				t.Errorf("AIConfigFromEnv accepted %s=%q", c.key, c.value)
			}
		})
	}
}

// TestAIIntegrationConfigTolerantNumberSpellings: Python's int()/float() strip
// surrounding whitespace.
func TestAIIntegrationConfigTolerantNumberSpellings(t *testing.T) {
	t.Setenv("SEC_AF_MAX_TURNS", " 75 ")
	t.Setenv("SEC_AF_AI_INITIAL_BACKOFF_SECONDS", " 1.5 ")
	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.MaxTurns != 75 {
		t.Errorf("MaxTurns = %d", cfg.MaxTurns)
	}
	approx(t, cfg.InitialBackoffSeconds, 1.5)
}

// TestProviderEnvOnlyIncludesPresentKeys ports
// test_config.py::test_provider_env_only_includes_present_keys.
func TestProviderEnvOnlyIncludesPresentKeys(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("OPENAI_API_KEY", "test-openai")
	t.Setenv("GITHUB_TOKEN", "test-gh")
	unsetEnv(t, "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GH_TOKEN")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}

	if env["OPENAI_API_KEY"] != "test-openai" {
		t.Errorf("OPENAI_API_KEY = %q", env["OPENAI_API_KEY"])
	}
	if env["GITHUB_TOKEN"] != "test-gh" {
		t.Errorf("GITHUB_TOKEN = %q", env["GITHUB_TOKEN"])
	}
	if _, present := env["OPENROUTER_API_KEY"]; present {
		t.Error("OPENROUTER_API_KEY leaked into provider_env")
	}
	if _, present := env["XDG_DATA_HOME"]; !present {
		t.Error("XDG_DATA_HOME missing from provider_env")
	}
}

// TestProviderEnvSkipsEmptyCredentials: the Python dict comprehension uses
// TRUTHINESS (`if (value := os.getenv(key))`), so a key set to "" is omitted —
// forwarding it would blank the variable in the harness subprocess (the Go SDK
// treats an empty Env value as "unset this").
func TestProviderEnvSkipsEmptyCredentials(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "real")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	if _, present := env["OPENROUTER_API_KEY"]; present {
		t.Error("an empty credential was forwarded; python truthiness drops it")
	}
	if env["ANTHROPIC_API_KEY"] != "real" {
		t.Errorf("ANTHROPIC_API_KEY = %q", env["ANTHROPIC_API_KEY"])
	}
}

// TestProviderEnvAforgeCommandOverride: getenv-with-default, so an explicitly
// empty value IS forwarded and only an absent key becomes "exec".
func TestProviderEnvAforgeCommandOverride(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	t.Setenv("AGENTFIELD_AFORGE_COMMAND", "run")
	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	if env["AGENTFIELD_AFORGE_COMMAND"] != "run" {
		t.Errorf("AGENTFIELD_AFORGE_COMMAND = %q, want run", env["AGENTFIELD_AFORGE_COMMAND"])
	}

	t.Setenv("AGENTFIELD_AFORGE_COMMAND", "")
	env, err = cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	if got, present := env["AGENTFIELD_AFORGE_COMMAND"]; !present || got != "" {
		t.Errorf("AGENTFIELD_AFORGE_COMMAND = %q/%v, want a present empty value", got, present)
	}
}

// TestProviderEnvCreatesXDGDataHome: Python calls os.makedirs(xdg, exist_ok=True)
// unconditionally, and the default is <tempdir>/opencode-shared-data.
func TestProviderEnvCreatesXDGDataHome(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "nested", "xdg")
	t.Setenv("XDG_DATA_HOME", target)

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	if env["XDG_DATA_HOME"] != target {
		t.Errorf("XDG_DATA_HOME = %q, want %q", env["XDG_DATA_HOME"], target)
	}
	if st, err := os.Stat(target); err != nil || !st.IsDir() {
		t.Errorf("ProviderEnv did not create %q: %v", target, err)
	}
}

// TestProviderEnvDefaultXDGPath: an EMPTY XDG_DATA_HOME is falsy in Python's
// `or`, so it falls back to <tempdir>/opencode-shared-data — not to "".
func TestProviderEnvDefaultXDGPath(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	want := filepath.Join(os.TempDir(), "opencode-shared-data")
	if env["XDG_DATA_HOME"] != want {
		t.Errorf("XDG_DATA_HOME = %q, want %q", env["XDG_DATA_HOME"], want)
	}
	if st, err := os.Stat(want); err != nil || !st.IsDir() {
		t.Errorf("ProviderEnv did not create the default dir %q: %v", want, err)
	}
}

// TestPinnedAgentFieldSDKExposesTheAforgeSurface ports
// test_config.py::test_pinned_agentfield_sdk_exposes_the_aforge_surface: the
// pinned SDK must accept the aforge harness settings app.py sends it.
//
// The Go SDK's HarnessConfig has ONE BinPath where Python has separate
// opencode_bin and aforge_bin, so the node picks the binary matching the
// provider (design §2). This asserts the config half of that mapping.
func TestPinnedAgentFieldSDKExposesTheAforgeSurface(t *testing.T) {
	unsetEnv(t, "SEC_AF_PROVIDER", "HARNESS_PROVIDER", "SEC_AF_AFORGE_BIN", "AFORGE_BIN")
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}

	hc := agent.HarnessConfig{
		Provider:       cfg.Provider,
		Model:          cfg.HarnessModel,
		MaxTurns:       cfg.MaxTurns,
		Env:            env,
		BinPath:        cfg.AforgeBin,
		PermissionMode: "auto",
	}
	if hc.Provider != "aforge" {
		t.Errorf("HarnessConfig.Provider = %q, want aforge", hc.Provider)
	}
	if hc.BinPath != "aforge" {
		t.Errorf("HarnessConfig.BinPath = %q, want aforge", hc.BinPath)
	}
	if hc.PermissionMode != "auto" {
		t.Errorf("HarnessConfig.PermissionMode = %q", hc.PermissionMode)
	}
}

// TestBudgetConfigUnmarshalSeedsDefaults: a BudgetConfig arriving over the wire
// (checkpoint, phase payload) must not silently become "0 hunters".
func TestBudgetConfigUnmarshalSeedsDefaults(t *testing.T) {
	var b BudgetConfig
	if err := json.Unmarshal([]byte(`{"max_provers": 7}`), &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.MaxProvers == nil || *b.MaxProvers != 7 {
		t.Errorf("MaxProvers = %#v", b.MaxProvers)
	}
	if b.MaxConcurrentHunters != 4 || b.MaxConcurrentProvers != 3 || b.HunterEarlyStopFileThreshold != 30 {
		t.Errorf("defaults lost: %#v", b)
	}
	approx(t, b.HuntBudgetPct, 0.45)
}

// TestAuditConfigUnmarshalSeedsDefaults.
func TestAuditConfigUnmarshalSeedsDefaults(t *testing.T) {
	var c AuditConfig
	if err := json.Unmarshal([]byte(`{"repo_path": "/r"}`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.RepoPath != "/r" {
		t.Errorf("RepoPath = %q", c.RepoPath)
	}
	if c.Depth != DepthStandard || c.SeverityThreshold != "low" || c.Provider != "aforge" {
		t.Errorf("defaults lost: %#v", c)
	}
	if !reflect.DeepEqual(c.ScanTypes, []string{"sast", "sca", "secrets", "config"}) {
		t.Errorf("ScanTypes = %#v", c.ScanTypes)
	}
	if !reflect.DeepEqual(c.ExcludePaths, []string{"tests/", "vendor/", "node_modules/", ".git/"}) {
		t.Errorf("ExcludePaths = %#v", c.ExcludePaths)
	}
	if c.IncludePaths != nil {
		t.Errorf("IncludePaths = %#v, want nil (python None)", c.IncludePaths)
	}
	if c.Budget.MaxConcurrentHunters != 4 {
		t.Errorf("nested budget defaults lost: %#v", c.Budget)
	}
}

// TestDefaultAuditConfigReturnsFreshSlices: pydantic's default_factory hands
// each model its own list; a shared package-level slice would let one audit's
// mutation leak into the next.
func TestDefaultAuditConfigReturnsFreshSlices(t *testing.T) {
	a := DefaultAuditConfig()
	b := DefaultAuditConfig()
	a.ScanTypes[0] = "mutated"
	if b.ScanTypes[0] != "sast" {
		t.Error("DefaultAuditConfig shares its slices between calls")
	}
}
