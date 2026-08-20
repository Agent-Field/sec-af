package phases

// A regression guard for the checked binders: everything the Go node ITSELF
// puts on a `.call` boundary must pass the binder on the other side.
//
// This is the failure mode the null checks introduce. The binders reject a
// `"findings": null` / `"languages": null` payload because pydantic does — but
// a Go struct with a nil slice marshals to exactly that, and every model in
// this port carries `default_factory=list` fields. If a producer ever builds a
// value with `schemas.X{...}` instead of `schemas.NewX()` (or forgets one list
// field), the phase downstream of it would start failing on a payload the
// Python node accepts, which is a WORSE divergence than the one the checks
// close. The Python side has no equivalent hazard: `model_dump()` of a
// `list[str]` field is always a list.
//
// Each case therefore takes a value built the way production builds it, renders
// it with afx.ToMap (what every reasoner returns), and binds it back.

import (
	"encoding/json"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	proveagent "github.com/Agent-Field/sec-af/go/internal/agents/prove"
	reconagent "github.com/Agent-Field/sec-af/go/internal/agents/recon"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// reconFromRaw builds a ReconResult the way recon_phase does — through the five
// harness-schema parsers — so the sub-model lists come from real production
// code rather than from a fixture.
func reconFromRaw(t *testing.T, arch schemas.ArchitectureMapRaw, flows schemas.DataFlowMapRaw,
	deps schemas.DependencyReportRaw, config schemas.ConfigReportRaw,
	sec schemas.SecurityContextRaw,
) schemas.ReconResult {
	t.Helper()
	out := schemas.NewReconResult()
	out.Architecture = reconagent.ParseArchitectureRaw(arch)
	out.DataFlows = reconagent.ParseDataFlowRaw(flows)
	out.Dependencies = reconagent.ParseDependencyReportRaw(deps)
	out.Config = reconagent.ParseConfigReportRaw(config)
	out.SecurityContext = reconagent.ParseSecurityContextRaw(sec)
	return out
}

func TestProducedPayloadsSurviveTheirBinders(t *testing.T) {
	t.Run("recon_phase output, everything empty", func(t *testing.T) {
		recon := reconFromRaw(t,
			schemas.NewArchitectureMapRaw(), schemas.NewDataFlowMapRaw(),
			schemas.NewDependencyReportRaw(), schemas.NewConfigReportRaw(),
			schemas.NewSecurityContextRaw())
		mustRebind(t, recon, func(m map[string]any) error {
			_, err := BindReconResult(m)
			return err
		})
	})

	t.Run("recon_phase output, every list populated", func(t *testing.T) {
		arch := schemas.NewArchitectureMapRaw()
		arch.Modules = []string{"auth | src/auth/ | python | Authentication"}
		arch.EntryPoints = []string{"http | POST /api/login | src/routes.py:42 | false"}
		arch.TrustBoundaries = []string{"API Gateway | external | internal | Rate limiting"}
		arch.Services = []string{"PostgreSQL | database | localhost:5432 | password"}
		arch.APIEndpoints = []string{"GET | /api/users | get_users | src/api.py:15 | true | false"}

		flows := schemas.NewDataFlowMapRaw()
		flows.Flows = []string{"request.body | sql.execute | false | src/db.py, src/routes.py"}
		flows.SanitizationPoints = []string{"src/utils.py:42 | sanitize_html | html_encoding | CWE-79"}
		flows.Sinks = []string{"sql_execute | src/db.py:55 | run_query | concatenation"}

		deps := schemas.NewDependencyReportRaw()
		deps.Sbom = []string{"express | 4.18.2 | npm | true | MIT"}
		deps.KnownCves = []string{"CVE-2023-1234 | lodash | 4.17.15 | 4.17.21 | 7.5 | true | unknown"}
		deps.Outdated = []string{"express | 4.17.0 | 4.18.2 | true"}

		config := schemas.NewConfigReportRaw()
		config.Secrets = []string{"aws_access_key | .env:3 | AKIA... | high | false"}
		config.Misconfigs = []string{"debug_mode | config.py:15 | DEBUG=True | Stack traces | Set DEBUG=False"}

		sec := schemas.NewSecurityContextRaw()
		sec.AuthModel = "jwt"
		sec.AuthDetails = "bearer"
		sec.CryptoUsage = []string{"AES | 256 | GCM | data encryption | false"}
		sec.SecuritySignals = []string{"CSRF protection enabled", "HSTS header present", "Runs in Docker"}

		recon := reconFromRaw(t, arch, flows, deps, config, sec)
		mustRebind(t, recon, func(m map[string]any) error {
			_, err := BindReconResult(m)
			return err
		})
		mustRebind(t, recon.Architecture, func(m map[string]any) error {
			_, err := BindArchitectureMap(m)
			return err
		})
		mustRebind(t, recon.SecurityContext, func(m map[string]any) error {
			_, err := BindSecurityContext(m)
			return err
		})
	})

	t.Run("hunt_phase output", func(t *testing.T) {
		hunt := schemas.NewHuntResult()
		hunt.Findings = []schemas.RawFinding{populatedRawFinding()}
		hunt.StrategiesRun = []string{"injection"}
		mustRebind(t, hunt, func(m map[string]any) error {
			_, err := BindHuntResult(m)
			return err
		})

		empty := schemas.NewHuntResult()
		mustRebind(t, empty, func(m map[string]any) error {
			_, err := BindHuntResult(m)
			return err
		})
	})

	t.Run("prove_phase output", func(t *testing.T) {
		// agents/prove.Fallback is the VerifiedFinding shape that reaches
		// remediation_phase and the prove checkpoint on the demotion path.
		reason := "verifier_error"
		verdict := "confirmed"
		for _, finding := range []schemas.VerifiedFinding{
			proveagent.Fallback(populatedRawFinding(), "boom", nil, nil),
			proveagent.Fallback(populatedRawFinding(), "boom", &reason, &verdict),
		} {
			mustRebind(t, finding, func(m map[string]any) error {
				_, err := BindVerifiedFinding(m)
				return err
			})
		}
	})
}

// populatedRawFinding is a RawFinding built the way an agent builds one —
// through the constructor, so the defaulted lists are seeded.
func populatedRawFinding() schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.HunterStrategy = "injection"
	f.Title = "SQL injection"
	f.Description = "unsanitized input reaches a query"
	f.FindingType = schemas.FindingTypeSast
	f.CweID = "CWE-89"
	f.CweName = "SQL Injection"
	f.FilePath = "app/db.py"
	f.StartLine = 10
	f.EndLine = 12
	f.CodeSnippet = "query(...)"
	f.EstimatedSeverity = schemas.SeverityHigh
	f.Confidence = schemas.ConfidenceHigh
	return f
}

// mustRebind puts value through the exact boundary a phase result crosses:
// afx.ToMap (what the reasoner returns), the SDK's JSON encode, the
// control-plane hop, and the decode into map[string]any the receiving handler
// gets — then the binder. afx.ToMap alone is NOT that boundary: it keeps field
// values TYPED on purpose, so the nested models would still be Go structs and
// the enums still schemas.Severity rather than string.
func mustRebind(t *testing.T, value any, bind func(map[string]any) error) {
	t.Helper()
	payload, err := afx.ToMap(value)
	if err != nil {
		t.Fatalf("afx.ToMap: %v", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := bind(decoded); err != nil {
		t.Fatalf("%T does not survive its own binder: %v\nwire payload: %s", value, err, raw)
	}
}
