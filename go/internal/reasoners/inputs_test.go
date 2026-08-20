package reasoners

// Tests for inputs.go — the transcription of each reasoner's Python signature.
//
// Validation contract:
//
//   - an ABSENT key yields the Python keyword default;
//   - a PRESENT key overrides it, even when its value is falsy (0, "", null),
//     which is what Python's keyword binding does;
//   - max_provers distinguishes "absent" (None -> the depth's cap) from an
//     explicit 0.

import (
	"context"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/phases"
)

func TestHunterInputDefaults(t *testing.T) {
	got, err := afx.Bind[HunterInput](map[string]any{"repo_path": "/r", "depth": "quick"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.MaxFilesWithoutSignal != 30 {
		t.Errorf("max_files_without_signal = %d, want 30", got.MaxFilesWithoutSignal)
	}

	got, err = afx.Bind[HunterInput](map[string]any{"max_files_without_signal": 0})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.MaxFilesWithoutSignal != 0 {
		t.Errorf("an explicit 0 must override the default, got %d", got.MaxFilesWithoutSignal)
	}
}

func TestReconPhaseInputDefaults(t *testing.T) {
	got, err := afx.Bind[ReconPhaseInput](map[string]any{"repo_path": "/r"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Depth != phases.DefaultDepth {
		t.Errorf("depth = %q, want %q", got.Depth, phases.DefaultDepth)
	}

	got, err = afx.Bind[ReconPhaseInput](map[string]any{"repo_path": "/r", "depth": ""})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Depth != "" {
		t.Errorf("an explicit empty depth must override the default, got %q", got.Depth)
	}
}

func TestHuntPhaseInputDefaults(t *testing.T) {
	got, err := afx.Bind[HuntPhaseInput](map[string]any{"repo_path": "/r"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Depth != phases.DefaultDepth {
		t.Errorf("depth = %q, want %q", got.Depth, phases.DefaultDepth)
	}
	if got.MaxConcurrentHunters != phases.DefaultMaxConcurrentHunters {
		t.Errorf("max_concurrent_hunters = %d, want %d", got.MaxConcurrentHunters, phases.DefaultMaxConcurrentHunters)
	}
	if got.EarlyStopFileThreshold != phases.DefaultEarlyStopFileThreshold {
		t.Errorf("early_stop_file_threshold = %d, want %d", got.EarlyStopFileThreshold, phases.DefaultEarlyStopFileThreshold)
	}
	// `ai_gate: Any | None = None` — absent binds to Python's None.
	if gate := phases.NewJSONAIGate(got.AIGate); gate != nil {
		t.Errorf("an absent ai_gate must be None, got %v", gate)
	}
}

// TestHuntPhaseInputBindsAIGate: hunt_phase is a REGISTERED reasoner, so a
// control-plane caller can send `ai_gate`. Python binds the raw JSON (the SDK
// passes an `Any`-hinted parameter straight through) and takes the
// `ai_gate is not None` branch; the Go adapter must reach the same branch and
// report the same CPython type name in the note it produces.
func TestHuntPhaseInputBindsAIGate(t *testing.T) {
	cases := []struct {
		value    any
		wantType string
	}{
		{map[string]any{"model": "x"}, "dict"},
		{[]any{"a"}, "list"},
		{"gate", "str"},
		{1, "int"},
		{1.5, "float"},
		{true, "bool"},
	}
	for _, tc := range cases {
		got, err := afx.Bind[HuntPhaseInput](map[string]any{"repo_path": "/r", "ai_gate": tc.value})
		if err != nil {
			t.Fatalf("Bind(%v): %v", tc.value, err)
		}
		gate := phases.NewJSONAIGate(got.AIGate)
		if gate == nil {
			t.Fatalf("ai_gate=%v must be non-None", tc.value)
		}
		_, err = gate.SelectStrategy(context.Background(), "", "standard", nil)
		want := "'" + tc.wantType + "' object has no attribute 'select_strategy'"
		if err == nil || err.Error() != want {
			t.Errorf("ai_gate=%v -> err %v, want %q", tc.value, err, want)
		}
	}

	// An explicit null is Python's None.
	got, err := afx.Bind[HuntPhaseInput](map[string]any{"repo_path": "/r", "ai_gate": nil})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if gate := phases.NewJSONAIGate(got.AIGate); gate != nil {
		t.Errorf("ai_gate=null must be None, got %v", gate)
	}
}

func TestProvePhaseInputDefaults(t *testing.T) {
	got, err := afx.Bind[ProvePhaseInput](map[string]any{"repo_path": "/r"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.MaxProvers != nil {
		t.Errorf("max_provers = %v, want nil (Python None)", *got.MaxProvers)
	}
	if got.MaxConcurrentProvers != phases.DefaultMaxConcurrentProvers {
		t.Errorf("max_concurrent_provers = %d, want %d", got.MaxConcurrentProvers, phases.DefaultMaxConcurrentProvers)
	}

	got, err = afx.Bind[ProvePhaseInput](map[string]any{"repo_path": "/r", "max_provers": 0})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.MaxProvers == nil || *got.MaxProvers != 0 {
		t.Errorf("an explicit 0 must bind as a pointer to 0, got %v", got.MaxProvers)
	}
}

func TestRemediationPhaseInputDefaults(t *testing.T) {
	got, err := afx.Bind[RemediationPhaseInput](map[string]any{"repo_path": "/r"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.MaxConcurrentRemediations != phases.DefaultMaxConcurrentRemediations {
		t.Errorf("max_concurrent_remediations = %d, want %d",
			got.MaxConcurrentRemediations, phases.DefaultMaxConcurrentRemediations)
	}
}
