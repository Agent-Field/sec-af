package hunt

// Tests for the twelve hunter modules under src/sec_af/agents/hunt.
//
// Validation contract (behaviour, not implementation):
//
//   - each hunter's SCAN PROMPT is byte-identical to the Python module's, for
//     the direct call AND for the call __init__.py's argument cascade makes;
//   - each hunter enriches with its own finding_type/strategy pair and its own
//     recon context, and the assembled HuntResult (findings, counters,
//     strategies_run) matches Python's model_dump();
//   - the four gated hunters (crypto, supply_chain, api_security,
//     business_logic/logic) make NO harness call when their gate is closed, and
//     return the exact empty shape Python returns — which is not the same shape
//     for all four;
//   - a scan that finds no locations returns without enriching, again in each
//     hunter's own empty shape;
//   - crypto partitions its usage contexts into security-critical and
//     non-security candidates by substring, in recon order, with a context
//     landing in both lists when it matches both tables;
//   - run_logic_hunter is indistinguishable from run_business_logic_hunter.

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// hunterCase describes one hunter for the table-driven tests. Direct calls the
// exported entry point the way src/sec_af/reasoners/hunt.py does — depth
// "standard" where the hunter accepts one, max_files_without_signal at its 30
// default — and Prompt builds the same call's scan prompt plus the recon
// context it embeds.
type hunterCase struct {
	Name        string
	FindingType string
	Strategy    string
	Direct      func(ctx context.Context, app appx.Harnesser, repoPath string, recon schemas.ReconResult) (schemas.HuntResult, error)
	Prompt      func(repoPath string, recon schemas.ReconResult) (string, string)
}

func hunterCases() []hunterCase {
	return []hunterCase{
		{"injection", "sast", "injection",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunInjectionHunter(ctx, app, repo, r, "standard", 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return injectionScanPrompt(repo, r, "standard", "30")
			}},
		{"xss", "sast", "xss",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunXSSHunter(ctx, app, repo, r, "standard", 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return xssScanPrompt(repo, r, "standard", "30")
			}},
		{"dos", "sast", "dos",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunDosHunter(ctx, app, repo, r, "standard", 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return dosScanPrompt(repo, r, "standard", "30")
			}},
		{"ssrf", "sast", "ssrf",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunSSRFHunter(ctx, app, repo, r, "standard", 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return ssrfScanPrompt(repo, r, "standard", "30")
			}},
		{"auth", "sast", "auth",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunAuthHunter(ctx, app, repo, r, "standard", 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return authScanPrompt(repo, r, "standard", "30")
			}},
		{"crypto", "sast", "crypto",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunCryptoHunter(ctx, app, repo, r, 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return cryptoScanPrompt(repo, r, "30")
			}},
		{"business_logic", "logic", "business_logic",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunBusinessLogicHunter(ctx, app, repo, r, "standard", 30, "")
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return businessLogicScanPrompt(repo, r, "standard", "30", "")
			}},
		{"logic", "logic", "business_logic",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunLogicHunter(ctx, app, repo, r, "standard", 30, "")
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return businessLogicScanPrompt(repo, r, "standard", "30", "")
			}},
		{"data_exposure", "sast", "data_exposure",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunDataExposureHunter(ctx, app, repo, r, 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return dataExposureScanPrompt(repo, r, "30")
			}},
		{"supply_chain", "sca", "supply_chain",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunSupplyChainHunter(ctx, app, repo, r, 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return supplyChainScanPrompt(repo, r, "30")
			}},
		{"config_secrets", "config", "config_secrets",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunConfigSecretsHunter(ctx, app, repo, r, 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return configSecretsScanPrompt(repo, r, "30")
			}},
		{"api_security", "api", "api_security",
			func(ctx context.Context, app appx.Harnesser, repo string, r schemas.ReconResult) (schemas.HuntResult, error) {
				return RunAPISecurityHunter(ctx, app, repo, r, 30)
			},
			func(repo string, r schemas.ReconResult) (string, string) {
				return apiSecurityScanPrompt(repo, r, "30")
			}},
	}
}

// TestDirectPromptDigestsMatchPython pins every hunter's DIRECT-call scan
// prompt, and the two enrichment prompts it would produce for the canned
// locations, by SHA-256 against the Python functions.
//
// The digest form is deliberate: the enrichment prompt embeds the same recon
// context as the scan prompt, so storing twenty-four more full texts would add
// a quarter-megabyte of testdata and no coverage. A digest mismatch is still an
// exact-bytes failure; the five full-text goldens below make the common
// failures readable.
func TestDirectPromptDigestsMatchPython(t *testing.T) {
	var golden struct {
		Scan   map[string]string   `json:"scan"`
		Enrich map[string][]string `json:"enrich"`
	}
	goldenJSON(t, "direct_prompt_sha256", &golden)
	recon := loadRecon(t, "recon_fixture")

	for _, hc := range hunterCases() {
		hc := hc
		t.Run(hc.Name, func(t *testing.T) {
			scanPrompt, reconContext := hc.Prompt(fixtureRepo, recon)
			if got, want := sha256Hex(ScanPrompt(scanPrompt)), golden.Scan[hc.Name]; got != want {
				// The digest compared here is of the FULL step-1 prompt (the
				// scan_locations wrapper around the hunter's own text), which
				// is what Python's _S4App recorded.
				t.Fatalf("scan prompt digest = %s, want %s", got, want)
			}
			wantEnrich := golden.Enrich[hc.Name]
			if len(wantEnrich) != len(cannedLocations()) {
				t.Fatalf("golden has %d enrich digests, want %d", len(wantEnrich), len(cannedLocations()))
			}
			for i, location := range cannedLocations() {
				got := sha256Hex(EnrichPrompt(location, hc.FindingType, hc.Strategy, reconContext))
				if got != wantEnrich[i] {
					t.Fatalf("enrich prompt %d digest = %s, want %s", i, got, wantEnrich[i])
				}
			}
		})
	}
}

// TestDirectPromptTextMatchesPython compares the full text for the five hunters
// whose direct-call prompt differs from the one the cascade produces (their
// early-stop value is 30 here and the depth string there).
//
// Every prompt golden in this package is the prompt as app.harness SAW it —
// i.e. the hunter's own text already wrapped in the shared scan_locations
// template — because that is where gen_golden.py's fake recorded it.
func TestDirectPromptTextMatchesPython(t *testing.T) {
	recon := loadRecon(t, "recon_fixture")
	byName := map[string]hunterCase{}
	for _, hc := range hunterCases() {
		byName[hc.Name] = hc
	}
	for _, name := range []string{"crypto", "data_exposure", "supply_chain", "config_secrets", "api_security"} {
		name := name
		t.Run(name, func(t *testing.T) {
			scanPrompt, _ := byName[name].Prompt(fixtureRepo, recon)
			assertTextEqual(t, "direct_prompt_"+name, ScanPrompt(scanPrompt), goldenText(t, "direct_prompt_"+name))
		})
	}
}

// TestLogicHunterIsBusinessLogicHunter pins logic.py's delegation: same prompt
// (down to the byte), same finding_type, same strategies_run.
func TestLogicHunterIsBusinessLogicHunter(t *testing.T) {
	recon := loadRecon(t, "recon_fixture")

	logicPrompt, logicContext := businessLogicScanPrompt(fixtureRepo, recon, "standard", "30", "")
	assertTextEqual(t, "logic == business_logic prompt", ScanPrompt(logicPrompt),
		goldenText(t, "prompt_business_logic_standard"))

	logicFake := newHuntFake(cannedLocations(), cannedEnriched())
	logicResult, err := RunLogicHunter(context.Background(), logicFake, fixtureRepo, recon, "standard", 30, "")
	if err != nil {
		t.Fatalf("RunLogicHunter: %v", err)
	}
	blFake := newHuntFake(cannedLocations(), cannedEnriched())
	blResult, err := RunBusinessLogicHunter(context.Background(), blFake, fixtureRepo, recon, "standard", 30, "")
	if err != nil {
		t.Fatalf("RunBusinessLogicHunter: %v", err)
	}
	if !reflect.DeepEqual(scrubIDs(jsonTree(t, logicResult)), scrubIDs(jsonTree(t, blResult))) {
		t.Fatalf("run_logic_hunter and run_business_logic_hunter disagree%s",
			diffJSON(scrubIDs(jsonTree(t, logicResult)), scrubIDs(jsonTree(t, blResult))))
	}
	if got := logicResult.StrategiesRun; !reflect.DeepEqual(got, []string{"business_logic"}) {
		t.Fatalf("strategies_run = %v, want [business_logic] — logic never names itself", got)
	}
	if logicContext == "" {
		t.Fatal("recon context is empty")
	}
}

// TestHunterResultsMatchPython runs every hunter end to end over the canned
// two-location scan and compares the whole HuntResult against Python's
// model_dump().
func TestHunterResultsMatchPython(t *testing.T) {
	var golden map[string]map[string]any
	goldenJSON(t, "hunter_results", &golden)
	recon := loadRecon(t, "recon_fixture")

	for _, hc := range hunterCases() {
		hc := hc
		t.Run(hc.Name, func(t *testing.T) {
			want, ok := golden[hc.Name]
			if !ok {
				t.Fatalf("no hunter_results golden for %s", hc.Name)
			}
			fake := newHuntFake(cannedLocations(), cannedEnriched())
			got, err := hc.Direct(context.Background(), fake, fixtureRepo, recon)
			if err != nil {
				t.Fatalf("%s: %v", hc.Name, err)
			}
			if len(fake.scanPrompts()) != 1 {
				t.Fatalf("want 1 scan call, got %d", len(fake.scanPrompts()))
			}
			if len(fake.enrichPrompts()) != len(cannedLocations()) {
				t.Fatalf("want %d enrich calls, got %d", len(cannedLocations()), len(fake.enrichPrompts()))
			}
			gotTree := scrubIDs(jsonTree(t, got))
			wantTree := scrubIDs(jsonTree(t, want))
			if !reflect.DeepEqual(gotTree, wantTree) {
				t.Fatalf("%s HuntResult mismatch%s", hc.Name, diffJSON(gotTree, wantTree))
			}
		})
	}
}

// TestHunterEmptyLocationsMatchPython pins the "scanner found nothing" return
// for every hunter — one scan call, no enrichment, and each hunter's own empty
// shape (six bare, five naming their strategy).
func TestHunterEmptyLocationsMatchPython(t *testing.T) {
	var golden map[string]struct {
		ScanCalls   int            `json:"scan_calls"`
		EnrichCalls int            `json:"enrich_calls"`
		Want        map[string]any `json:"want"`
	}
	goldenJSON(t, "hunter_empty_locations", &golden)
	recon := loadRecon(t, "recon_fixture")

	for _, hc := range hunterCases() {
		hc := hc
		t.Run(hc.Name, func(t *testing.T) {
			want, ok := golden[hc.Name]
			if !ok {
				t.Fatalf("no hunter_empty_locations golden for %s", hc.Name)
			}
			fake := newHuntFake(nil, cannedEnriched())
			got, err := hc.Direct(context.Background(), fake, fixtureRepo, recon)
			if err != nil {
				t.Fatalf("%s: %v", hc.Name, err)
			}
			if len(fake.scanPrompts()) != want.ScanCalls {
				t.Errorf("scan calls = %d, want %d", len(fake.scanPrompts()), want.ScanCalls)
			}
			if len(fake.enrichPrompts()) != want.EnrichCalls {
				t.Errorf("enrich calls = %d, want %d", len(fake.enrichPrompts()), want.EnrichCalls)
			}
			gotTree := scrubIDs(jsonTree(t, got))
			wantTree := scrubIDs(jsonTree(t, want.Want))
			if !reflect.DeepEqual(gotTree, wantTree) {
				t.Fatalf("%s empty HuntResult mismatch%s", hc.Name, diffJSON(gotTree, wantTree))
			}
		})
	}
}

// TestHunterSkipsMatchPython pins the four gates: no harness call at all, and
// the exact empty shape each gate returns.
func TestHunterSkipsMatchPython(t *testing.T) {
	var golden map[string]struct {
		HarnessCalls int            `json:"harness_calls"`
		Want         map[string]any `json:"want"`
	}
	goldenJSON(t, "hunter_skips", &golden)

	rich := loadRecon(t, "recon_fixture")

	// gen_golden.py's no_crypto: the rich recon with an empty crypto_usage.
	noCrypto := loadRecon(t, "recon_fixture")
	noCrypto.SecurityContext = schemas.SecurityContext{
		AuthModel:         "jwt",
		AuthDetails:       "x",
		CryptoUsage:       []schemas.CryptoUsage{},
		FrameworkSecurity: append([]string(nil), rich.SecurityContext.FrameworkSecurity...),
		SecurityHeaders:   append([]string(nil), rich.SecurityContext.SecurityHeaders...),
		DeploymentSignals: append([]string(nil), rich.SecurityContext.DeploymentSignals...),
	}

	// gen_golden.py's no_deps: direct_count back to 0.
	noDeps := loadRecon(t, "recon_fixture")
	noDeps.Dependencies = schemas.NewDependencyReport()
	noDeps.Dependencies.DirectCount = 0
	noDeps.Dependencies.TransitiveCount = 9

	// gen_golden.py's no_api: an empty api_surface.
	noAPI := loadRecon(t, "recon_fixture")
	noAPI.Architecture.APISurface = []schemas.APIEndpoint{}

	cases := map[string]func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error){
		"crypto_no_usage": func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error) {
			return RunCryptoHunter(ctx, app, fixtureRepo, noCrypto, 30)
		},
		"crypto_empty_recon": func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error) {
			return RunCryptoHunter(ctx, app, fixtureRepo, emptyRecon(), 30)
		},
		"supply_chain_no_direct_deps": func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error) {
			return RunSupplyChainHunter(ctx, app, fixtureRepo, noDeps, 30)
		},
		"api_security_no_surface": func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error) {
			return RunAPISecurityHunter(ctx, app, fixtureRepo, noAPI, 30)
		},
		"business_logic_quick": func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error) {
			return RunBusinessLogicHunter(ctx, app, fixtureRepo, rich, "quick", 30, "")
		},
		"logic_quick": func(ctx context.Context, app appx.Harnesser) (schemas.HuntResult, error) {
			return RunLogicHunter(ctx, app, fixtureRepo, rich, "quick", 30, "")
		},
	}
	if len(cases) != len(golden) {
		t.Fatalf("golden has %d skip cases, the test covers %d", len(golden), len(cases))
	}

	for name, run := range cases {
		name, run := name, run
		t.Run(name, func(t *testing.T) {
			want := golden[name]
			fake := newHuntFake(cannedLocations(), cannedEnriched())
			got, err := run(context.Background(), fake)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(fake.Harnesses) != want.HarnessCalls {
				t.Errorf("harness calls = %d, want %d", len(fake.Harnesses), want.HarnessCalls)
			}
			gotTree := scrubIDs(jsonTree(t, got))
			wantTree := scrubIDs(jsonTree(t, want.Want))
			if !reflect.DeepEqual(gotTree, wantTree) {
				t.Fatalf("%s HuntResult mismatch%s", name, diffJSON(gotTree, wantTree))
			}
		})
	}
}

// TestReconContextBlocksMatchPython pins the two inline JSON context builders
// (which are hunt's own code, not context.py's) against json.dumps(..., indent=2)
// of the same model_dump, for a rich and an all-defaults recon.
func TestReconContextBlocksMatchPython(t *testing.T) {
	rich := loadRecon(t, "recon_fixture")
	empty := emptyRecon()

	// dos, ssrf and xss declare three byte-identical copies of the helper.
	for _, name := range []string{"dos", "ssrf", "xss"} {
		assertTextEqual(t, "recon_context_block_"+name,
			entryFlowContextBlock(rich), goldenText(t, "recon_context_block_"+name))
	}
	assertTextEqual(t, "recon_context_block_dos_empty",
		entryFlowContextBlock(empty), goldenText(t, "recon_context_block_dos_empty"))

	assertTextEqual(t, "recon_context_block_business_logic",
		businessLogicContextBlock(rich), goldenText(t, "recon_context_block_business_logic"))
	assertTextEqual(t, "recon_context_block_business_logic_empty",
		businessLogicContextBlock(empty), goldenText(t, "recon_context_block_business_logic_empty"))
}

// TestReconContextBlockTruncation states the slice limits, which differ between
// the two builders (10 entry points / 10 flows vs 15 / 20 endpoints / 20 flows).
//
// The rich fixture holds 17 entry points, 20 endpoints and 20 flows — enough
// for the entry-point limits but exactly at the endpoint/flow ceilings — so the
// counts are asserted against a synthetic recon carrying 30 of each.
func TestReconContextBlockTruncation(t *testing.T) {
	recon := emptyRecon()
	for i := 0; i < 30; i++ {
		recon.Architecture.EntryPoints = append(recon.Architecture.EntryPoints,
			schemas.EntryPoint{Kind: "http", Identifier: "e", FilePath: "f.py", Line: i})
		recon.Architecture.APISurface = append(recon.Architecture.APISurface,
			schemas.APIEndpoint{Method: "GET", Path: "/p", Handler: "h", FilePath: "f.py", Line: i})
		recon.DataFlows.Flows = append(recon.DataFlows.Flows,
			schemas.DataFlow{Source: "s", Sink: "k", Path: []schemas.ReconDataFlowStep{}, Files: []string{}})
	}

	entryFlow := entryFlowContextBlock(recon)
	if got := strings.Count(entryFlow, `"kind":`); got != 10 {
		t.Errorf("entryFlowContextBlock kept %d entry points, want 10", got)
	}
	if got := strings.Count(entryFlow, `"sanitized":`); got != 10 {
		t.Errorf("entryFlowContextBlock kept %d data flows, want 10", got)
	}
	if strings.Contains(entryFlow, `"api_surface"`) {
		t.Error("entryFlowContextBlock must not carry api_surface")
	}

	businessLogic := businessLogicContextBlock(recon)
	if got := strings.Count(businessLogic, `"kind":`); got != 15 {
		t.Errorf("businessLogicContextBlock kept %d entry points, want 15", got)
	}
	if got := strings.Count(businessLogic, `"handler":`); got != 20 {
		t.Errorf("businessLogicContextBlock kept %d api endpoints, want 20", got)
	}
	if got := strings.Count(businessLogic, `"sanitized":`); got != 20 {
		t.Errorf("businessLogicContextBlock kept %d data flows, want 20", got)
	}
	if !strings.Contains(businessLogic, `"auth_details":`) {
		t.Error("businessLogicContextBlock must carry auth_details")
	}
}

// ---------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------

func strptr(s string) *string { return &s }
func boolptr(b bool) *bool    { return &b }

// cryptoUsageCases mirrors gen_golden.py's crypto usage-context table. A nil
// entry is Python's None usage_context.
func cryptoUsageCases() map[string][]*string {
	return map[string][]*string{
		"mixed": {
			strptr("password hashing"),
			strptr("file integrity checksum"),
			strptr("etag generation for cache"),
			strptr("TLS session key derivation"),
			strptr("unrelated purpose"),
			nil,
			strptr(""),
		},
		"none":       {strptr("unrelated purpose"), strptr("widget rendering")},
		"both_terms": {strptr("auth token cache")},
	}
}

func cryptoUsageRecon(contexts []*string) schemas.ReconResult {
	recon := emptyRecon()
	usage := make([]schemas.CryptoUsage, 0, len(contexts))
	for _, c := range contexts {
		usage = append(usage, schemas.CryptoUsage{Algorithm: "MD5", UsageContext: c, IsWeak: boolptr(true)})
	}
	recon.SecurityContext.CryptoUsage = usage
	return recon
}

// TestCryptoUsagePartitionMatchesPython pins _usage_contexts,
// _filter_contexts_by_terms and should_run_crypto_hunter, plus the prompt each
// partition produces.
func TestCryptoUsagePartitionMatchesPython(t *testing.T) {
	var golden map[string]struct {
		UsageContexts    []string `json:"usage_contexts"`
		SecurityCritical []string `json:"security_critical"`
		NonSecurity      []string `json:"non_security"`
		ShouldRun        bool     `json:"should_run"`
	}
	goldenJSON(t, "crypto_usage_partition", &golden)

	for name, contexts := range cryptoUsageCases() {
		name, contexts := name, contexts
		t.Run(name, func(t *testing.T) {
			want, ok := golden[name]
			if !ok {
				t.Fatalf("no crypto_usage_partition golden for %s", name)
			}
			recon := cryptoUsageRecon(contexts)

			if got := cryptoUsageContexts(recon); !reflect.DeepEqual(got, want.UsageContexts) {
				t.Errorf("usage contexts = %#v, want %#v", got, want.UsageContexts)
			}
			gotCritical := filterContextsByTerms(cryptoUsageContexts(recon), cryptoSecurityCriticalTerms)
			if !reflect.DeepEqual(gotCritical, want.SecurityCritical) {
				t.Errorf("security-critical = %#v, want %#v", gotCritical, want.SecurityCritical)
			}
			gotNon := filterContextsByTerms(cryptoUsageContexts(recon), cryptoNonSecurityTerms)
			if !reflect.DeepEqual(gotNon, want.NonSecurity) {
				t.Errorf("non-security = %#v, want %#v", gotNon, want.NonSecurity)
			}
			if got := ShouldRunCryptoHunter(recon); got != want.ShouldRun {
				t.Errorf("should_run = %v, want %v", got, want.ShouldRun)
			}

			prompt, _ := cryptoScanPrompt(fixtureRepo, recon, "30")
			assertTextEqual(t, "crypto_prompt_"+name, ScanPrompt(prompt), goldenText(t, "crypto_prompt_"+name))
		})
	}
}

// TestCryptoTermTables pins the two substring tables verbatim.
func TestCryptoTermTables(t *testing.T) {
	var golden struct {
		SecurityCritical []string `json:"security_critical"`
		NonSecurity      []string `json:"non_security"`
	}
	goldenJSON(t, "crypto_term_tables", &golden)
	if !reflect.DeepEqual(cryptoSecurityCriticalTerms, golden.SecurityCritical) {
		t.Errorf("_SECURITY_CRITICAL_TERMS = %#v, want %#v", cryptoSecurityCriticalTerms, golden.SecurityCritical)
	}
	if !reflect.DeepEqual(cryptoNonSecurityTerms, golden.NonSecurity) {
		t.Errorf("_NON_SECURITY_TERMS = %#v, want %#v", cryptoNonSecurityTerms, golden.NonSecurity)
	}
}

// TestCryptoCandidateListFallback pins the `else "none"` spelling both
// candidate lines use when nothing matched.
func TestCryptoCandidateListFallback(t *testing.T) {
	if got := cryptoCandidateList(nil); got != "none" {
		t.Errorf("empty candidates render as %q, want %q", got, "none")
	}
	if got := cryptoCandidateList([]string{"a", "b"}); got != "a, b" {
		t.Errorf("candidates render as %q, want %q", got, "a, b")
	}
}

// ---------------------------------------------------------------------------
// auth / business_logic knobs
// ---------------------------------------------------------------------------

// TestAuthDepthLabelMatchesPython pins _depth_label, including the strip() that
// makes it differ from config.NormalizeDepth.
func TestAuthDepthLabelMatchesPython(t *testing.T) {
	var golden map[string]string
	goldenJSON(t, "auth_depth_label", &golden)
	if len(golden) == 0 {
		t.Fatal("auth_depth_label golden is empty")
	}
	for in, want := range golden {
		if got := authDepthLabel(in); got != want {
			t.Errorf("authDepthLabel(%q) = %q, want %q", in, got, want)
		}
	}
	// The strip() is what separates this from the lenient normalizer used
	// everywhere else in the pipeline.
	if authDepthLabel(" THOROUGH ") != "thorough" {
		t.Error("authDepthLabel must trim before matching")
	}
}

// TestAuthTargetCWEs pins the CWE list joined into {{TARGET_CWES}}.
func TestAuthTargetCWEs(t *testing.T) {
	var golden []string
	goldenJSON(t, "auth_target_cwes", &golden)
	if !reflect.DeepEqual(authTargetCWEs, golden) {
		t.Fatalf("_TARGET_CWES = %#v, want %#v", authTargetCWEs, golden)
	}
}

// TestBusinessLogicEnabledMatchesPython pins the depth gate.
func TestBusinessLogicEnabledMatchesPython(t *testing.T) {
	var golden map[string]bool
	goldenJSON(t, "business_logic_enabled", &golden)
	if len(golden) == 0 {
		t.Fatal("business_logic_enabled golden is empty")
	}
	for in, want := range golden {
		if got := IsBusinessLogicHunterEnabled(in); got != want {
			t.Errorf("IsBusinessLogicHunterEnabled(%q) = %v, want %v", in, got, want)
		}
		if got := IsLogicHunterEnabled(in); got != want {
			t.Errorf("IsLogicHunterEnabled(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestBusinessLogicDepthPromptMatchesPython pins the optional
// "- Additional depth guidance: ..." tail, which only a deliberate caller can
// trigger (the argument cascade never delivers it).
func TestBusinessLogicDepthPromptMatchesPython(t *testing.T) {
	recon := loadRecon(t, "recon_small")
	got, _ := businessLogicScanPrompt(fixtureRepo, recon, "thorough", "30", ThoroughDepthPrompt)
	assertTextEqual(t, "business_logic_prompt_with_depth_prompt", ScanPrompt(got),
		goldenText(t, "business_logic_prompt_with_depth_prompt"))

	if !strings.HasSuffix(got, "\n- Additional depth guidance: "+ThoroughDepthPrompt) {
		t.Fatal("the depth-guidance tail must be appended last, on its own line")
	}
	without, _ := businessLogicScanPrompt(fixtureRepo, recon, "thorough", "30", "")
	if strings.Contains(without, "Additional depth guidance") {
		t.Fatal("an empty depth_prompt must add nothing")
	}
}

// ---------------------------------------------------------------------------
// direct ports of tests/test_hunt_crypto.py
// ---------------------------------------------------------------------------

// cryptoTestRecon ports tests/test_hunt_crypto.py::_recon_with_crypto_usage —
// an otherwise-default recon carrying one non-security and one security-critical
// crypto usage.
func cryptoTestRecon() schemas.ReconResult {
	recon := emptyRecon()
	recon.SecurityContext.AuthModel = "session"
	recon.SecurityContext.AuthDetails = "cookie"
	recon.SecurityContext.CryptoUsage = []schemas.CryptoUsage{
		{Algorithm: "MD5", UsageContext: strptr("file integrity checksum"), IsWeak: boolptr(true)},
		{Algorithm: "SHA1", UsageContext: strptr("password hashing"), IsWeak: boolptr(true)},
	}
	return recon
}

// TestCryptoHunterPromptIncludesContextAwareRiskGating ports
// tests/test_hunt_crypto.py::test_crypto_hunter_prompt_includes_context_aware_risk_gating.
func TestCryptoHunterPromptIncludesContextAwareRiskGating(t *testing.T) {
	fake := newHuntFake(nil, cannedEnriched())
	if _, err := RunCryptoHunter(context.Background(), fake, ".", cryptoTestRecon(), 30); err != nil {
		t.Fatalf("RunCryptoHunter: %v", err)
	}
	prompt := fake.onlyScanPrompt(t)

	for _, want := range []string{
		"- Focus CWEs: CWE-326, CWE-327, CWE-328, CWE-330, CWE-916, CWE-259, CWE-321, CWE-798",
		"Prioritize weak crypto findings only when used in security-sensitive contexts",
		"file integrity checksum",
		"password hashing",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("crypto prompt is missing %q", want)
		}
	}
	// And the gating itself: the checksum context is a NON-security candidate
	// while the password one is security-critical.
	if !strings.Contains(prompt, "- Security-critical usage candidates: password hashing\n") {
		t.Error("security-critical candidates line is wrong")
	}
	if !strings.Contains(prompt, "- Non-security usage candidates: file integrity checksum\n") {
		t.Error("non-security candidates line is wrong")
	}
}

// TestCryptoHunterSkipsWhenReconHasNoCryptoUsage ports
// tests/test_hunt_crypto.py::test_crypto_hunter_skips_when_recon_has_no_crypto_usage:
// the bare HuntResult() shape and, crucially, NO harness call at all (the
// Python test asserts `app.prompt == ""`).
func TestCryptoHunterSkipsWhenReconHasNoCryptoUsage(t *testing.T) {
	recon := emptyRecon()
	recon.SecurityContext.CryptoUsage = []schemas.CryptoUsage{}

	fake := newHuntFake(cannedLocations(), cannedEnriched())
	got, err := RunCryptoHunter(context.Background(), fake, ".", recon, 30)
	if err != nil {
		t.Fatalf("RunCryptoHunter: %v", err)
	}
	if !reflect.DeepEqual(got, schemas.NewHuntResult()) {
		t.Errorf("result = %+v, want the bare HuntResult()", got)
	}
	if len(fake.Harnesses) != 0 {
		t.Errorf("made %d harness calls, want 0", len(fake.Harnesses))
	}
}

// TestHuntPromptTemplatesAreEmbedded guards every template this package loads
// with prompts.MustLoad — which panics on a missing name — plus logic.txt,
// which ships in the Python tree and is deliberately loaded by nobody
// (logic.py forwards to business_logic.py without reading it).
func TestHuntPromptTemplatesAreEmbedded(t *testing.T) {
	loaded := []string{
		scanPromptPath, enrichPromptPath,
		injectionPromptPath, xssPromptPath, dosPromptPath, ssrfPromptPath, authPromptPath,
		cryptoPromptPath, businessLogicPromptPath, dataExposurePromptPath,
		supplyChainPromptPath, configSecretsPromptPath, apiSecurityPromptPath,
	}
	for _, rel := range loaded {
		if body, err := prompts.Load(rel); err != nil || body == "" {
			t.Errorf("prompts.Load(%q) = %d bytes, err %v", rel, len(body), err)
		}
	}
	if body, err := prompts.Load("hunt/logic.txt"); err != nil || body == "" {
		t.Errorf("hunt/logic.txt must stay embedded even though no code path reads it: %v", err)
	}
}
