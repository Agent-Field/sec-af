package afx

import (
	"encoding/json"
	"reflect"
	"testing"
)

// depthDefaulted models the schemas-package pattern: pydantic defaults that are
// not the Go zero value are seeded in UnmarshalJSON, so Bind on a map missing
// those keys still produces the Python default.
type depthDefaulted struct {
	RepoPath          string   `json:"repo_path"`
	Depth             string   `json:"depth"`
	SeverityThreshold string   `json:"severity_threshold"`
	ScanTypes         []string `json:"scan_types"`
	MaxProvers        *int     `json:"max_provers"`
}

func (d *depthDefaulted) UnmarshalJSON(b []byte) error {
	type alias depthDefaulted
	v := alias{
		Depth:             "standard",
		SeverityThreshold: "low",
		ScanTypes:         []string{"sast", "sca", "secrets", "config"},
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*d = depthDefaulted(v)
	return nil
}

// TestBindSeedsPydanticDefaults: Bind must run T's UnmarshalJSON so absent keys
// pick up the pydantic default rather than the Go zero value — the behaviour
// `AuditInput(**payload)` has in Python.
func TestBindSeedsPydanticDefaults(t *testing.T) {
	got, err := Bind[depthDefaulted](map[string]any{"repo_path": "/tmp/repo"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	want := depthDefaulted{
		RepoPath:          "/tmp/repo",
		Depth:             "standard",
		SeverityThreshold: "low",
		ScanTypes:         []string{"sast", "sca", "secrets", "config"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Bind = %#v, want %#v", got, want)
	}
}

// TestBindOverridesDefaults: keys present in the input win over the seed.
func TestBindOverridesDefaults(t *testing.T) {
	got, err := Bind[depthDefaulted](map[string]any{
		"repo_path":   "/tmp/repo",
		"depth":       "thorough",
		"scan_types":  []any{"sast"},
		"max_provers": 4,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Depth != "thorough" {
		t.Errorf("Depth = %q, want thorough", got.Depth)
	}
	if !reflect.DeepEqual(got.ScanTypes, []string{"sast"}) {
		t.Errorf("ScanTypes = %#v", got.ScanTypes)
	}
	if got.MaxProvers == nil || *got.MaxProvers != 4 {
		t.Errorf("MaxProvers = %#v, want 4", got.MaxProvers)
	}
}

// TestBindAcceptsJSONNumbers: reasoner inputs arrive over the control plane as
// JSON, so every number is a float64 by the time it reaches a handler. Bind
// must land those in int/float fields alike.
func TestBindAcceptsJSONNumbers(t *testing.T) {
	type numeric struct {
		Turns int     `json:"turns"`
		Cost  float64 `json:"cost"`
	}
	got, err := Bind[numeric](map[string]any{"turns": float64(50), "cost": float64(1)})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Turns != 50 || got.Cost != 1 {
		t.Errorf("Bind = %#v, want {50 1}", got)
	}
}

// TestBindTypeMismatchIsAnError mirrors pydantic's ValidationError.
func TestBindTypeMismatchIsAnError(t *testing.T) {
	type numeric struct {
		Turns int `json:"turns"`
	}
	if _, err := Bind[numeric](map[string]any{"turns": "fifty"}); err == nil {
		t.Fatal("Bind should reject a string in an int field")
	}
}

// TestToMapUsesJSONTagsAndKeepsValuesTyped.
func TestToMapUsesJSONTagsAndKeepsValuesTyped(t *testing.T) {
	type inner struct {
		N int `json:"n"`
	}
	type outer struct {
		RepoPath string   `json:"repo_path"`
		Depth    string   `json:"depth"`
		Nested   inner    `json:"nested"`
		Tags     []string `json:"tags"`
		Skipped  string   `json:"-"`
		unset    string   //nolint:unused // unexported fields are skipped
	}
	got, err := ToMap(outer{RepoPath: "/r", Depth: "quick", Nested: inner{N: 3}, Tags: []string{"a"}, Skipped: "x"})
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	if got["repo_path"] != "/r" || got["depth"] != "quick" {
		t.Errorf("ToMap = %#v", got)
	}
	if _, present := got["-"]; present {
		t.Error(`ToMap emitted the json:"-" field`)
	}
	if _, present := got["Skipped"]; present {
		t.Error(`ToMap emitted the json:"-" field under its Go name`)
	}
	if _, present := got["unset"]; present {
		t.Error("ToMap emitted an unexported field")
	}
	// Values stay typed — not flattened into map[string]any.
	if _, ok := got["nested"].(inner); !ok {
		t.Errorf("ToMap flattened a nested struct: %T", got["nested"])
	}
	if _, ok := got["tags"].([]string); !ok {
		t.Errorf("ToMap changed a slice's type: %T", got["tags"])
	}
}

// TestToMapFlattensEmbedded mirrors encoding/json's anonymous-field flattening.
func TestToMapFlattensEmbedded(t *testing.T) {
	type Base struct {
		A string `json:"a"`
	}
	type derived struct {
		Base
		B string `json:"b"`
	}
	got, err := ToMap(derived{Base: Base{A: "1"}, B: "2"})
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("ToMap = %#v, want flattened {a:1 b:2}", got)
	}
}

// TestToMapRejectsNonStructs.
func TestToMapRejectsNonStructs(t *testing.T) {
	if _, err := ToMap(map[string]any{"a": 1}); err == nil {
		t.Error("ToMap should reject a map")
	}
	var p *struct{ A int }
	if _, err := ToMap(p); err == nil {
		t.Error("ToMap should reject a nil pointer")
	}
}

// TestToMapThenBindRoundTrips: the phase code hands ToMap output to app.Call
// and the handler Binds it back.
func TestToMapThenBindRoundTrips(t *testing.T) {
	in := depthDefaulted{RepoPath: "/r", Depth: "thorough", SeverityThreshold: "high", ScanTypes: []string{"sast"}}
	m, err := ToMap(in)
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	back, err := Bind[depthDefaulted](m)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Errorf("round trip = %#v, want %#v", back, in)
	}
}
