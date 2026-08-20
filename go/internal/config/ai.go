package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// AIIntegrationConfig ports config.py AIIntegrationConfig — every field is a
// `Field(default_factory=lambda: os.getenv(...))`, so the values come from the
// environment at construction time.
//
// OpencodeServer is `str | None` in Python and a pointer here: nil means the
// variable was absent entirely, which is distinguishable from a variable set to
// the empty string (see AIConfigFromEnv).
type AIIntegrationConfig struct {
	Provider              string  `json:"provider"`
	HarnessModel          string  `json:"harness_model"`
	AIModel               string  `json:"ai_model"`
	MaxTurns              int     `json:"max_turns"`
	MaxRetries            int     `json:"max_retries"`
	InitialBackoffSeconds float64 `json:"initial_backoff_seconds"`
	MaxBackoffSeconds     float64 `json:"max_backoff_seconds"`
	OpencodeBin           string  `json:"opencode_bin"`
	AforgeBin             string  `json:"aforge_bin"`
	OpencodeServer        *string `json:"opencode_server"`
}

// AIConfigFromEnv ports AIIntegrationConfig.from_env() — which is just `cls()`,
// i.e. run every default_factory.
//
// Env precedence, verbatim from the lambdas:
//
//	provider                  SEC_AF_PROVIDER > HARNESS_PROVIDER > "aforge"
//	harness_model             SEC_AF_MODEL > HARNESS_MODEL > "minimax/minimax-m2.5"
//	ai_model                  SEC_AF_AI_MODEL > AI_MODEL > SEC_AF_MODEL > "minimax/minimax-m2.5"
//	max_turns                 int(SEC_AF_MAX_TURNS or "50")
//	max_retries               int(SEC_AF_AI_MAX_RETRIES or "3")
//	initial_backoff_seconds   float(SEC_AF_AI_INITIAL_BACKOFF_SECONDS or "2.0")
//	max_backoff_seconds       float(SEC_AF_AI_MAX_BACKOFF_SECONDS or "8.0")
//	opencode_bin              SEC_AF_OPENCODE_BIN > "opencode"
//	aforge_bin                SEC_AF_AFORGE_BIN > AFORGE_BIN > "aforge"
//	opencode_server           SEC_AF_OPENCODE_SERVER > OPENCODE_SERVER > None
//
// Python parity: `os.getenv(key, fallback)` returns the variable's value
// whenever the KEY EXISTS, including when it is set to the empty string — the
// fallback only applies to an absent key. So this uses os.LookupEnv, not
// os.Getenv (which cannot tell "" from unset).
//
// A malformed numeric value is an ERROR, because Python's int()/float() raises
// inside the default_factory, which runs while app.py is being imported — the
// node fails to boot. Callers must propagate rather than substitute a default.
func AIConfigFromEnv() (AIIntegrationConfig, error) {
	c := AIIntegrationConfig{
		Provider:     envChain("aforge", "SEC_AF_PROVIDER", "HARNESS_PROVIDER"),
		HarnessModel: envChain("minimax/minimax-m2.5", "SEC_AF_MODEL", "HARNESS_MODEL"),
		AIModel:      envChain("minimax/minimax-m2.5", "SEC_AF_AI_MODEL", "AI_MODEL", "SEC_AF_MODEL"),
		OpencodeBin:  envChain("opencode", "SEC_AF_OPENCODE_BIN"),
		AforgeBin:    envChain("aforge", "SEC_AF_AFORGE_BIN", "AFORGE_BIN"),
	}

	var err error
	if c.MaxTurns, err = envInt("SEC_AF_MAX_TURNS", 50); err != nil {
		return AIIntegrationConfig{}, err
	}
	if c.MaxRetries, err = envInt("SEC_AF_AI_MAX_RETRIES", 3); err != nil {
		return AIIntegrationConfig{}, err
	}
	if c.InitialBackoffSeconds, err = envFloat("SEC_AF_AI_INITIAL_BACKOFF_SECONDS", 2.0); err != nil {
		return AIIntegrationConfig{}, err
	}
	if c.MaxBackoffSeconds, err = envFloat("SEC_AF_AI_MAX_BACKOFF_SECONDS", 8.0); err != nil {
		return AIIntegrationConfig{}, err
	}

	// `os.getenv("SEC_AF_OPENCODE_SERVER", os.getenv("OPENCODE_SERVER"))`: the
	// inner getenv has NO default, so it yields None for an absent key — which
	// then becomes the outer default. Both absent => None.
	if v, ok := os.LookupEnv("SEC_AF_OPENCODE_SERVER"); ok {
		c.OpencodeServer = &v
	} else if v, ok := os.LookupEnv("OPENCODE_SERVER"); ok {
		c.OpencodeServer = &v
	}

	return c, nil
}

// providerEnvKeys is the exact tuple config.py's provider_env() scans, in order.
var providerEnvKeys = [...]string{
	"OPENROUTER_API_KEY",
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"GOOGLE_API_KEY",
	"GITHUB_TOKEN",
	"GH_TOKEN",
}

// ProviderEnv ports AIIntegrationConfig.provider_env():
//
//	env = {key: value for key in env_keys if (value := os.getenv(key))}
//	env["AGENTFIELD_AFORGE_COMMAND"] = os.getenv("AGENTFIELD_AFORGE_COMMAND", "exec")
//	xdg = os.getenv("XDG_DATA_HOME") or os.path.join(tempfile.gettempdir(), "opencode-shared-data")
//	os.makedirs(xdg, exist_ok=True)
//	env["XDG_DATA_HOME"] = xdg
//	return env
//
// Parity details:
//
//   - The six credential keys use TRUTHINESS (`if (value := os.getenv(key))`),
//     so a key set to the empty string is omitted, not forwarded as "".
//   - AGENTFIELD_AFORGE_COMMAND uses getenv-with-default, so an explicitly
//     empty value IS forwarded as "" and only an absent key becomes "exec".
//   - XDG_DATA_HOME uses `or`, i.e. truthiness again: an empty value falls back
//     to the temp-dir path.
//   - The directory is created eagerly. Python raises on failure inside the
//     Agent constructor, so this returns the error instead of continuing with a
//     directory the harness subprocess cannot use.
//
// Go's os.TempDir() resolves $TMPDIR (else /tmp) on unix, where Python's
// tempfile.gettempdir() also consults TEMP and TMP. On Linux and in the
// container both yield the same path.
func (c AIIntegrationConfig) ProviderEnv() (map[string]string, error) {
	env := make(map[string]string, len(providerEnvKeys)+2)
	for _, key := range providerEnvKeys {
		if v := os.Getenv(key); v != "" {
			env[key] = v
		}
	}

	aforgeCommand := "exec"
	if v, ok := os.LookupEnv("AGENTFIELD_AFORGE_COMMAND"); ok {
		aforgeCommand = v
	}
	env["AGENTFIELD_AFORGE_COMMAND"] = aforgeCommand

	xdg := os.Getenv("XDG_DATA_HOME")
	if xdg == "" {
		xdg = filepath.Join(os.TempDir(), "opencode-shared-data")
	}
	if err := os.MkdirAll(xdg, 0o755); err != nil {
		return nil, fmt.Errorf("config.ProviderEnv: create XDG_DATA_HOME %q: %w", xdg, err)
	}
	env["XDG_DATA_HOME"] = xdg

	return env, nil
}

// envChain reproduces a nested `os.getenv(a, os.getenv(b, ... default))`: the
// FIRST key that EXISTS wins, even when its value is empty.
func envChain(def string, keys ...string) string {
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			return v
		}
	}
	return def
}

// envInt reproduces `int(os.getenv(key, str(def)))`.
//
// Python's int() tolerates surrounding whitespace, so TrimSpace runs first; it
// also accepts underscore digit separators ("5_0"), which strconv does not —
// deliberately not reproduced, as no deployment spells a turn count that way.
func envInt(key string, def int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not an integer: %w", key, raw, err)
	}
	return n, nil
}

// envFloat reproduces `float(os.getenv(key, str(def)))`.
func envFloat(key string, def float64) (float64, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a float: %w", key, raw, err)
	}
	return f, nil
}
