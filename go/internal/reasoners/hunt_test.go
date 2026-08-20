package reasoners

// Tests for src/sec_af/reasoners/hunt.py.
//
// Validation contract (behaviour, derived from the Python module):
//
//   - every hunter reasoner emits its own "X starting" note with its own tags,
//     BEFORE the agent function runs;
//   - run_logic_bugs_hunter emits NO note of its own and is otherwise
//     indistinguishable from run_business_logic_hunter;
//   - _recon_model seeds the five required nested models plus
//     security_context={"auth_model":"unknown","auth_details":""} and then
//     OVERLAYS recon_context wholesale (dict.update semantics — a partial
//     security_context replaces the seed and fails validation);
//   - the seven hunters whose Python signature declares `depth` receive the
//     caller's max_files_without_signal; the five that do not always run with
//     30 (the TypeError cascade drops the keyword);
//   - run_deduplicator validates its findings as RawFindings and its
//     recon_context as a ReconResult WITHOUT the _recon_model seed;
//   - each adapter returns the agent result's model_dump() key set.

import (
	"context"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

// hunterAdapter is one hunter reasoner under test.
type hunterAdapter struct {
	Name string
	Fn   func(context.Context, appx.App, HunterInput) (map[string]any, error)
	Note string
	Tags []string
	// TakesDepth reports whether the Python agent signature declares `depth`,
	// which is what decides whether max_files_without_signal survives
	// _run_hunter's TypeError cascade.
	TakesDepth bool
	// Gated hunters return early without a harness call when the recon context
	// gives them nothing to do, so their prompt cannot be inspected.
	Gated bool
}

func hunterAdapters() []hunterAdapter {
	return []hunterAdapter{
		{"run_injection_hunter", RunInjectionHunter, "Injection hunter starting", []string{"hunt", "injection"}, true, false},
		{"run_dos_hunter", RunDosHunter, "DoS hunter starting", []string{"hunt", "dos"}, true, false},
		{"run_ssrf_hunter", RunSSRFHunter, "SSRF hunter starting", []string{"hunt", "ssrf"}, true, false},
		{"run_auth_hunter", RunAuthHunter, "Auth hunter starting", []string{"hunt", "auth"}, true, false},
		{"run_xss_hunter", RunXSSHunter, "XSS hunter starting", []string{"hunt", "xss"}, true, false},
		{"run_crypto_hunter", RunCryptoHunter, "Crypto hunter starting", []string{"hunt", "crypto"}, false, true},
		{"run_business_logic_hunter", RunBusinessLogicHunter, "Business logic hunter starting", []string{"hunt", "business-logic"}, true, false},
		{"run_data_exposure_hunter", RunDataExposureHunter, "Data exposure hunter starting", []string{"hunt", "data-exposure"}, false, false},
		{"run_supply_chain_hunter", RunSupplyChainHunter, "Supply chain hunter starting", []string{"hunt", "supply-chain"}, false, true},
		{"run_config_secrets_hunter", RunConfigSecretsHunter, "Config secrets hunter starting", []string{"hunt", "config-secrets"}, false, false},
		{"run_api_security_hunter", RunAPISecurityHunter, "API security hunter starting", []string{"hunt", "api-security"}, false, true},
	}
}

func TestHunterAdaptersEmitTheirNote(t *testing.T) {
	for _, tc := range hunterAdapters() {
		t.Run(tc.Name, func(t *testing.T) {
			fake := newScanFake()
			if _, err := tc.Fn(context.Background(), fake, HunterInput{
				RepoPath:              t.TempDir(),
				ReconContext:          map[string]any{},
				Depth:                 "standard",
				MaxFilesWithoutSignal: DefaultMaxFilesWithoutSignal,
			}); err != nil {
				t.Fatalf("%s: %v", tc.Name, err)
			}
			assertNote(t, fake, tc.Note, tc.Tags...)
		})
	}
}

// TestHunterMaxFilesCascadeParity is the observable half of _run_hunter's
// TypeError cascade: with max_files_without_signal=50, the hunters whose
// signature takes `depth` put 50 in their prompt and the ones that do not put
// 30, because the third cascade shape passes neither keyword.
//
// VERIFIED against the Python source by binding each hunter's real signature
// against each cascade shape on the repo's own interpreter.
func TestHunterMaxFilesCascadeParity(t *testing.T) {
	const custom = 50

	for _, tc := range hunterAdapters() {
		if tc.Gated {
			continue // no harness call to inspect
		}
		t.Run(tc.Name, func(t *testing.T) {
			fake := newScanFake()
			if _, err := tc.Fn(context.Background(), fake, HunterInput{
				RepoPath:              t.TempDir(),
				ReconContext:          map[string]any{},
				Depth:                 "thorough",
				MaxFilesWithoutSignal: custom,
			}); err != nil {
				t.Fatalf("%s: %v", tc.Name, err)
			}
			if len(fake.Harnesses) == 0 {
				t.Fatalf("%s made no harness call", tc.Name)
			}
			want := "30"
			if tc.TakesDepth {
				want = "50"
			}
			assertPromptHasFileBudget(t, fake.Harnesses[0].Prompt, want)
		})
	}
}

// TestRunLogicBugsHunterDelegates pins the alias: no note of its own, and the
// same prompt run_business_logic_hunter produces for the same input.
func TestRunLogicBugsHunterDelegates(t *testing.T) {
	repo := t.TempDir()
	in := HunterInput{
		RepoPath:              repo,
		ReconContext:          map[string]any{},
		Depth:                 "thorough",
		MaxFilesWithoutSignal: 42,
	}

	aliasFake := newScanFake()
	aliasResult, err := RunLogicBugsHunter(context.Background(), aliasFake, in)
	if err != nil {
		t.Fatalf("RunLogicBugsHunter: %v", err)
	}

	directFake := newScanFake()
	directResult, err := RunBusinessLogicHunter(context.Background(), directFake, in)
	if err != nil {
		t.Fatalf("RunBusinessLogicHunter: %v", err)
	}

	// The alias emits exactly the delegate's note — one note, not two, and not
	// a "logic bugs" one.
	assertNote(t, aliasFake, "Business logic hunter starting", "hunt", "business-logic")

	if len(aliasFake.Harnesses) != len(directFake.Harnesses) {
		t.Fatalf("harness calls: alias %d, direct %d", len(aliasFake.Harnesses), len(directFake.Harnesses))
	}
	for i := range aliasFake.Harnesses {
		if aliasFake.Harnesses[i].Prompt != directFake.Harnesses[i].Prompt {
			t.Errorf("prompt %d differs between the alias and the delegate", i)
		}
	}
	if len(aliasResult) != len(directResult) {
		t.Errorf("result key count: alias %d, direct %d", len(aliasResult), len(directResult))
	}
}

// TestReconModelSeeds pins _recon_model's normalization.
func TestReconModelSeeds(t *testing.T) {
	t.Run("empty context binds with the seeded defaults", func(t *testing.T) {
		recon, err := reconModel(map[string]any{})
		if err != nil {
			t.Fatalf("reconModel: %v", err)
		}
		if recon.SecurityContext.AuthModel != "unknown" {
			t.Errorf("auth_model = %q, want %q", recon.SecurityContext.AuthModel, "unknown")
		}
		// Python parity: the hunt.py seed uses "" for auth_details, NOT the
		// "unknown" recon_phase's quick-depth placeholder uses.
		if recon.SecurityContext.AuthDetails != "" {
			t.Errorf("auth_details = %q, want the empty string", recon.SecurityContext.AuthDetails)
		}
		if recon.LinesOfCode != 0 || recon.FileCount != 0 {
			t.Errorf("metrics = (%d, %d), want (0, 0)", recon.LinesOfCode, recon.FileCount)
		}
	})

	t.Run("caller values overlay the seed", func(t *testing.T) {
		recon, err := reconModel(map[string]any{
			"languages":     []any{"python"},
			"lines_of_code": float64(4200),
		})
		if err != nil {
			t.Fatalf("reconModel: %v", err)
		}
		if len(recon.Languages) != 1 || recon.Languages[0] != "python" {
			t.Errorf("languages = %v, want [python]", recon.Languages)
		}
		if recon.LinesOfCode != 4200 {
			t.Errorf("lines_of_code = %d, want 4200", recon.LinesOfCode)
		}
	})

	t.Run("a partial security_context replaces the seed wholesale and fails", func(t *testing.T) {
		// Python parity: dict.update replaces the KEY, so the auth_details seed
		// is lost and SecurityContext validation fails.
		if _, err := reconModel(map[string]any{
			"security_context": map[string]any{"auth_model": "jwt"},
		}); err == nil {
			t.Fatal("want a validation error for the partial security_context")
		}
	})
}

// TestRunDeduplicatorValidatesStrictly pins the two binds run_deduplicator does
// — RawFinding per finding, and a RAW ReconResult (no _recon_model seed).
func TestRunDeduplicatorValidatesStrictly(t *testing.T) {
	t.Run("an incomplete recon_context fails", func(t *testing.T) {
		fake := newScanFake()
		_, err := RunDeduplicator(context.Background(), fake, DeduplicatorInput{
			Findings:     nil,
			ReconContext: map[string]any{},
			RepoPath:     t.TempDir(),
		})
		if err == nil {
			t.Fatal("want a validation error: run_deduplicator does not seed defaults")
		}
		assertNote(t, fake, "Deduplicator starting", "hunt", "dedup")
	})

	t.Run("a malformed finding fails", func(t *testing.T) {
		fake := newScanFake()
		_, err := RunDeduplicator(context.Background(), fake, DeduplicatorInput{
			Findings:     []map[string]any{{"title": "malformed"}},
			ReconContext: fullReconContext(),
			RepoPath:     t.TempDir(),
		})
		if err == nil {
			t.Fatal("want a validation error for a RawFinding missing required fields")
		}
	})

	t.Run("a well-formed request returns a HuntResult dump", func(t *testing.T) {
		fake := newScanFake()
		got, err := RunDeduplicator(context.Background(), fake, DeduplicatorInput{
			Findings:     []map[string]any{rawFindingPayload()},
			ReconContext: fullReconContext(),
			RepoPath:     t.TempDir(),
		})
		if err != nil {
			t.Fatalf("RunDeduplicator: %v", err)
		}
		for _, key := range []string{
			"findings", "chains", "total_raw", "deduplicated_count", "chain_count",
			"strategies_run", "hunt_duration_seconds",
		} {
			if _, ok := got[key]; !ok {
				t.Errorf("result is missing the %q key (HuntResult.model_dump())", key)
			}
		}
	})
}
