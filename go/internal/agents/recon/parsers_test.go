package recon

// Validation contract for src/sec_af/agents/recon/_parsers.py, checked against
// fixtures produced by the REAL Python helpers (go/scripts/gen_golden.py):
//
//   - splitPipe caps the field count, keeping surplus pipes in the last field,
//     strips each field, and right-pads short rows with "".
//   - parseBool/parseInt/parseFloat/parseFileLine/isNA reproduce CPython's
//     coercions exactly, including the underscore digit separator, the
//     rfind(":") split and the "non-positive line means no line" rule.
//   - Each parse_*_raw turns a flat *Raw model into the structured model with
//     the same field values Python produces, byte for byte after JSON encoding.

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// primitivesGolden mirrors testdata/golden/parse_primitives.json.
type primitivesGolden struct {
	SplitPipe []struct {
		S        string   `json:"s"`
		Expected int      `json:"expected"`
		Want     []string `json:"want"`
	} `json:"split_pipe"`
	ParseBool []struct {
		S    string `json:"s"`
		Want *bool  `json:"want"`
	} `json:"parse_bool"`
	ParseInt []struct {
		S    string `json:"s"`
		Want int    `json:"want"`
	} `json:"parse_int"`
	ParseIntDefault9 []struct {
		S    string `json:"s"`
		Want int    `json:"want"`
	} `json:"parse_int_default9"`
	ParseFloat []struct {
		S    string  `json:"s"`
		Want *string `json:"want"` // Python repr(), or null
	} `json:"parse_float"`
	ParseFileLine []struct {
		S    string `json:"s"`
		Path string `json:"path"`
		Line int    `json:"line"`
	} `json:"parse_file_line"`
	IsNA []struct {
		S    string `json:"s"`
		Want bool   `json:"want"`
	} `json:"is_na"`
}

// TestParsePrimitives ports the behavior of _split_pipe, _parse_bool,
// _parse_int, _parse_float, _parse_file_line and _is_na.
func TestParsePrimitives(t *testing.T) {
	var g primitivesGolden
	goldenJSON(t, "parse_primitives", &g)

	t.Run("split_pipe", func(t *testing.T) {
		if len(g.SplitPipe) == 0 {
			t.Fatal("golden has no split_pipe cases")
		}
		for _, c := range g.SplitPipe {
			got := splitPipe(c.S, c.Expected)
			if !reflect.DeepEqual(got, c.Want) {
				t.Errorf("splitPipe(%q, %d) = %q, want %q", c.S, c.Expected, got, c.Want)
			}
		}
	})

	t.Run("parse_bool", func(t *testing.T) {
		for _, c := range g.ParseBool {
			got := parseBool(c.S)
			if !equalBoolPtr(got, c.Want) {
				t.Errorf("parseBool(%q) = %s, want %s", c.S, fmtBoolPtr(got), fmtBoolPtr(c.Want))
			}
		}
	})

	t.Run("parse_int", func(t *testing.T) {
		for _, c := range g.ParseInt {
			if got := parseInt(c.S, 0); got != c.Want {
				t.Errorf("parseInt(%q, 0) = %d, want %d", c.S, got, c.Want)
			}
		}
		for _, c := range g.ParseIntDefault9 {
			if got := parseInt(c.S, 9); got != c.Want {
				t.Errorf("parseInt(%q, 9) = %d, want %d", c.S, got, c.Want)
			}
		}
	})

	t.Run("parse_float", func(t *testing.T) {
		for _, c := range g.ParseFloat {
			got := parseFloat(c.S)
			switch {
			case c.Want == nil && got != nil:
				t.Errorf("parseFloat(%q) = %v, want nil", c.S, *got)
			case c.Want != nil && got == nil:
				t.Errorf("parseFloat(%q) = nil, want %s", c.S, *c.Want)
			case c.Want != nil && got != nil:
				// Compared through pyfmt.FormatFloat (an exact port of Python's
				// str(float)) so inf/nan compare by spelling instead of by an
				// equality operator that NaN fails.
				if spelled := pyfmt.FormatFloat(*got); spelled != *c.Want {
					t.Errorf("parseFloat(%q) = %s, want %s", c.S, spelled, *c.Want)
				}
			}
		}
	})

	t.Run("parse_file_line", func(t *testing.T) {
		for _, c := range g.ParseFileLine {
			path, line := parseFileLine(c.S)
			if path != c.Path || line != c.Line {
				t.Errorf("parseFileLine(%q) = (%q, %d), want (%q, %d)", c.S, path, line, c.Path, c.Line)
			}
		}
	})

	t.Run("is_na", func(t *testing.T) {
		for _, c := range g.IsNA {
			if got := isNA(c.S); got != c.Want {
				t.Errorf("isNA(%q) = %v, want %v", c.S, got, c.Want)
			}
		}
	})
}

// parseGolden is the {input, want} envelope every parse_<model>.json uses.
type parseGolden struct {
	Input json.RawMessage `json:"input"`
	Want  any             `json:"want"`
}

// runParserGolden decodes the golden's flat *Raw input into T, runs parse, and
// compares the JSON shape of the result with Python's model_dump().
func runParserGolden[Raw any, Out any](t *testing.T, name string, parse func(Raw) Out) {
	t.Helper()
	var g parseGolden
	goldenJSON(t, name, &g)

	var raw Raw
	if err := json.Unmarshal(g.Input, &raw); err != nil {
		t.Fatalf("%s: decode input into %T: %v", name, raw, err)
	}

	got := scrubIDs(jsonTree(t, parse(raw)))
	if !reflect.DeepEqual(got, g.Want) {
		t.Errorf("%s mismatch with Python%s", name, diffJSON(t, got, g.Want))
	}
}

// TestParseArchitectureRaw ports parse_architecture_raw.
func TestParseArchitectureRaw(t *testing.T) {
	runParserGolden(t, "parse_architecture", ParseArchitectureRaw)
}

// TestParseDataFlowRaw ports parse_data_flow_raw.
func TestParseDataFlowRaw(t *testing.T) {
	runParserGolden(t, "parse_data_flow", ParseDataFlowRaw)
}

// TestParseDependencyReportRaw ports parse_dependency_report_raw.
func TestParseDependencyReportRaw(t *testing.T) {
	runParserGolden(t, "parse_dependency_report", ParseDependencyReportRaw)
}

// TestParseConfigReportRaw ports parse_config_report_raw.
func TestParseConfigReportRaw(t *testing.T) {
	runParserGolden(t, "parse_config_report", ParseConfigReportRaw)
}

// TestParseSecurityContextRaw ports parse_security_context_raw.
func TestParseSecurityContextRaw(t *testing.T) {
	runParserGolden(t, "parse_security_context", ParseSecurityContextRaw)
}

// TestParsersEmitEmptyListsNotNull pins that every list a parser produces is
// non-nil, so it serializes as `[]` like a pydantic default_factory=list field
// and never as `null`. The orchestrator round-trips these models through the
// control plane as JSON, so a null where Python sends [] would break the
// receiving model_validate.
func TestParsersEmitEmptyListsNotNull(t *testing.T) {
	arch := ParseArchitectureRaw(schemas.NewArchitectureMapRaw())
	df := ParseDataFlowRaw(schemas.NewDataFlowMapRaw())
	dep := ParseDependencyReportRaw(schemas.NewDependencyReportRaw())
	cfg := ParseConfigReportRaw(schemas.NewConfigReportRaw())
	sec := ParseSecurityContextRaw(schemas.NewSecurityContextRaw())

	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"ArchitectureMap", arch, `{"app_type":"unknown","modules":[],"entry_points":[],"trust_boundaries":[],"services":[],"api_surface":[]}`},
		{"DataFlowMap", df, `{"flows":[],"sanitization_points":[],"sinks":[]}`},
		{"DependencyReport", dep, `{"sbom":[],"known_cves":[],"outdated":[],"direct_count":0,"transitive_count":0}`},
		{"ConfigReport", cfg, `{"secrets":[],"misconfigs":[]}`},
		{"SecurityContext", sec, `{"auth_model":"","auth_details":"","crypto_usage":[],"framework_security":[],"security_headers":[],"deployment_signals":[]}`},
	} {
		b, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(b) != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, b, tc.want)
		}
	}
}

// TestParseArchitectureRawRouteDerivation pins the EntryPoint.route rule, which
// is derived rather than parsed: the identifier doubles as the route only when
// it contains a "/".
func TestParseArchitectureRawRouteDerivation(t *testing.T) {
	raw := schemas.NewArchitectureMapRaw()
	raw.EntryPoints = []string{
		"http | POST /api/login | src/routes.py:42 | false",
		"cli | migrate | src/cli.py:8 | true",
	}
	got := ParseArchitectureRaw(raw)

	if got.EntryPoints[0].Route == nil || *got.EntryPoints[0].Route != "POST /api/login" {
		t.Errorf("route for an identifier containing '/' = %v, want the identifier", got.EntryPoints[0].Route)
	}
	if got.EntryPoints[1].Route != nil {
		t.Errorf("route for an identifier without '/' = %q, want nil", *got.EntryPoints[1].Route)
	}
	// method is never populated by the parser; it keeps the pydantic default.
	if got.EntryPoints[0].Method != nil {
		t.Errorf("method = %q, want nil (never parsed)", *got.EntryPoints[0].Method)
	}
}

// TestParseDependencyReportRawCounts pins that direct/transitive counts come
// only from the sbom rows and that an unparseable `direct` flag counts as
// transitive.
func TestParseDependencyReportRawCounts(t *testing.T) {
	raw := schemas.NewDependencyReportRaw()
	raw.Sbom = []string{
		"a | 1 | pypi | true | MIT",
		"b | 1 | pypi | false | MIT",
		"c | 1 | pypi | garbage | MIT",
	}
	// known_cves rows carry their own `direct` flag but must not move the
	// counters.
	raw.KnownCves = []string{"CVE-1 | a | 1 | 2 | 9.8 | true | true"}

	got := ParseDependencyReportRaw(raw)
	if got.DirectCount != 1 || got.TransitiveCount != 2 {
		t.Errorf("counts = (direct %d, transitive %d), want (1, 2)", got.DirectCount, got.TransitiveCount)
	}
}

// TestSecuritySignalBucketingIsFirstMatchWins pins the ordering of the two
// substring tables: a signal matching BOTH a header term and a deployment term
// lands in security_headers, because the header test runs first.
func TestSecuritySignalBucketingIsFirstMatchWins(t *testing.T) {
	raw := schemas.NewSecurityContextRaw()
	raw.SecuritySignals = []string{"HSTS header set by the Docker ingress"}

	got := ParseSecurityContextRaw(raw)
	if len(got.SecurityHeaders) != 1 || len(got.DeploymentSignals) != 0 || len(got.FrameworkSecurity) != 0 {
		t.Errorf("buckets = headers %v, deployment %v, framework %v; want the signal in headers only",
			got.SecurityHeaders, got.DeploymentSignals, got.FrameworkSecurity)
	}
}

func equalBoolPtr(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func fmtBoolPtr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}
