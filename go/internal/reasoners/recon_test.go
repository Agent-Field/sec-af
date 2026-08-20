package reasoners

// Tests for src/sec_af/reasoners/recon.py.
//
// Validation contract:
//
//   - each of the five adapters emits its own note (message + tags) before the
//     agent function runs;
//   - the two deep-recon adapters materialize `architecture` with
//     ArchitectureMap(**architecture), which has no required field — an empty
//     or absent dict binds to the pydantic defaults rather than failing;
//   - each adapter returns the agent result's model_dump() key set.

import (
	"context"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/appx"
)

func TestReconAdapterNotes(t *testing.T) {
	repo := t.TempDir()

	t.Run("run_architecture_mapper", func(t *testing.T) {
		fake := newScanFake()
		got, err := RunArchitectureMapper(context.Background(), fake, RepoPathInput{RepoPath: repo})
		if err != nil {
			t.Fatalf("RunArchitectureMapper: %v", err)
		}
		assertNote(t, fake, "Architecture mapper starting", "recon", "architecture")
		assertHasKeys(t, got, "app_type", "modules", "entry_points", "api_surface", "trust_boundaries")
	})

	t.Run("run_dependency_auditor", func(t *testing.T) {
		fake := newScanFake()
		got, err := RunDependencyAuditor(context.Background(), fake, RepoPathInput{RepoPath: repo})
		if err != nil {
			t.Fatalf("RunDependencyAuditor: %v", err)
		}
		assertNote(t, fake, "Dependency auditor starting", "recon", "dependencies")
		assertHasKeys(t, got, "direct_count", "transitive_count", "known_cves")
	})

	t.Run("run_config_scanner", func(t *testing.T) {
		fake := newScanFake()
		got, err := RunConfigScanner(context.Background(), fake, RepoPathInput{RepoPath: repo})
		if err != nil {
			t.Fatalf("RunConfigScanner: %v", err)
		}
		assertNote(t, fake, "Config scanner starting", "recon", "config")
		assertHasKeys(t, got, "secrets", "misconfigs")
	})

	t.Run("run_data_flow_mapper", func(t *testing.T) {
		fake := newScanFake()
		got, err := RunDataFlowMapper(context.Background(), fake, ArchitectureInput{
			RepoPath:     repo,
			Architecture: map[string]any{},
		})
		if err != nil {
			t.Fatalf("RunDataFlowMapper: %v", err)
		}
		assertNote(t, fake, "Data flow mapper starting", "recon", "data-flow")
		assertHasKeys(t, got, "flows", "sanitization_points")
	})

	t.Run("run_security_context_profiler", func(t *testing.T) {
		fake := newScanFake()
		got, err := RunSecurityContextProfiler(context.Background(), fake, ArchitectureInput{
			RepoPath:     repo,
			Architecture: map[string]any{},
		})
		if err != nil {
			t.Fatalf("RunSecurityContextProfiler: %v", err)
		}
		assertNote(t, fake, "Security context profiler starting", "recon", "security-context")
		assertHasKeys(t, got, "auth_model", "auth_details", "crypto_usage", "framework_security")
	})
}

// TestDeepReconAcceptsAbsentArchitecture pins the "no required field" half of
// the contract: `ArchitectureMap(**{})` succeeds in Python, so a request that
// omits `architecture` entirely must not fail.
func TestDeepReconAcceptsAbsentArchitecture(t *testing.T) {
	fake := newScanFake()
	if _, err := RunDataFlowMapper(context.Background(), fake, ArchitectureInput{RepoPath: t.TempDir()}); err != nil {
		t.Fatalf("RunDataFlowMapper with no architecture: %v", err)
	}
}

func assertHasKeys(t *testing.T, got map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := got[key]; !ok {
			t.Errorf("result is missing the %q key", key)
		}
	}
}

var _ appx.App = (*appx.Fake)(nil)
