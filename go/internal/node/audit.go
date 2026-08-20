package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/orch"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/reasoners"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// audit.go ports the `audit(...)` reasoner body (src/sec_af/app.py:123).

// nowMonotonic is `time.monotonic()`. It is a variable so a test can pin the
// two duration fields the pipeline stamps; production never reassigns it.
//
// Go's time.Now carries a monotonic reading that Sub prefers over the wall
// clock, so a DIFFERENCE has exactly Python's time.monotonic() semantics.
var nowMonotonic = time.Now

// ErrBadInput marks a ValueError-class failure raised INSIDE audit()'s
// try/except, i.e. one Python maps to
//
//	except ValueError as exc: raise HTTPException(400, detail={"error": str(exc)})
//
// Wrap an error with %w against this sentinel to have IsBadInput classify it.
var ErrBadInput = errors.New("bad input")

// IsBadInput reports whether err is one of the ValueError-class failures the
// audit pipeline can raise from inside the mapped region.
//
// THREE families reach it, all of them ValueError subclasses in Python:
//
//  1. `ValueError(f"Unknown checkpoint phase: {phase}")` from
//     orchestrator.run_from_checkpoint -> *orch.UnknownCheckpointPhaseError.
//  2. `Model.model_validate(payload)` / `Model(**payload)` anywhere inside the
//     try — app.py:181 ReconResult, :191 HuntResult, :203 and :217
//     VerifiedFinding, plus orchestrator.py's `_read_checkpoint`. pydantic's
//     ValidationError SUBCLASSES ValueError (VERIFIED on the pinned
//     interpreter: `ValidationError.__mro__` is
//     `(ValidationError, ValueError, Exception, BaseException, object)`), so
//     EVERY schema failure inside the try takes the 400 branch, not the 500 one
//     -> *phases.ValidationError.
//  3. `json.loads` on a corrupt checkpoint file: `json.JSONDecodeError` is also
//     a ValueError -> encoding/json's *SyntaxError / *UnmarshalTypeError, which
//     are what orch.ReadCheckpoint / ReadCheckpointList and afx.Bind return for
//     the same input.
//
// TWO OTHER ValueErrors exist in the audit flow and are DELIBERATELY not routed
// here, because Python raises them OUTSIDE the try:
//
//	orchestrator = AuditOrchestrator(app=app, input=audit_input)   # AuditConfig.from_input -> ValueError on a bad depth
//	repo_path = _resolve_repo(repo_url)                            # ValueError("git clone failed: ...")
//	orchestrator.repo_path = ...
//	try:
//	    ...                                                        # <- only failures in here reach the 400 mapping
//
// FastAPI turns an uncaught exception into a generic 500, so a bad `depth` and
// a failed clone are 500s in Python, not 400s. DESIGN.md §0.2 ("reproduce, do
// not improve") says to keep it that way; auditHandler therefore maps those two
// call sites to 500 explicitly and says so at each site.
//
// The distinction is observable twice over: the status code a client branches
// on, and the fact that the 400 branch emits NO `app.note` while the 500 branch
// emits `Note("Audit pipeline failed: ...", "audit", "error")`.
func IsBadInput(err error) bool {
	var unknownPhase *orch.UnknownCheckpointPhaseError
	if errors.As(err, &unknownPhase) {
		return true
	}
	var validation *phases.ValidationError
	if errors.As(err, &validation) {
		return true
	}
	// json.JSONDecodeError and pydantic's coercion failures are both ValueError
	// subclasses; encoding/json reports the same two conditions as these types.
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return true
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return true
	}
	return errors.Is(err, ErrBadInput)
}

// AuditRequest transcribes the `audit(...)` signature (app.py:124-144) — all
// twenty parameters, with their exact names, types and defaults.
//
// Nil pointers stand for Python's `None`; nil slices stand for the four
// `list[str] | None = None` parameters, whose `or` fallbacks live in
// ToAuditInput.
type AuditRequest struct {
	RepoURL              string   `json:"repo_url"`
	Depth                string   `json:"depth"`
	Branch               string   `json:"branch"`
	CommitSha            *string  `json:"commit_sha"`
	BaseCommitSha        *string  `json:"base_commit_sha"`
	SeverityThreshold    string   `json:"severity_threshold"`
	ScanTypes            []string `json:"scan_types"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	MaxCostUsd           *float64 `json:"max_cost_usd"`
	MaxProvers           *int     `json:"max_provers"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
	IncludePaths         []string `json:"include_paths"`
	ExcludePaths         []string `json:"exclude_paths"`
	IsPr                 bool     `json:"is_pr"`
	PrID                 *string  `json:"pr_id"`
	PostPrComments       bool     `json:"post_pr_comments"`
	FailOnFindings       bool     `json:"fail_on_findings"`
	// EnableDast is accepted and then DISCARDED — see ToAuditInput.
	EnableDast           bool    `json:"enable_dast"`
	ResumeFromCheckpoint *string `json:"resume_from_checkpoint"`
}

// NewAuditRequest returns the three non-empty keyword defaults of audit():
// depth="standard", branch="main", severity_threshold="low". Every other
// parameter's default is None / [] / False, which is the Go zero value.
func NewAuditRequest() AuditRequest {
	return AuditRequest{
		Depth:             "standard",
		Branch:            "main",
		SeverityThreshold: "low",
	}
}

// UnmarshalJSON seeds audit()'s keyword defaults before decoding.
func (a *AuditRequest) UnmarshalJSON(b []byte) error {
	*a = NewAuditRequest()
	type alias AuditRequest
	return json.Unmarshal(b, (*alias)(a))
}

// ToAuditInput ports the `AuditInput(...)` construction at app.py:146.
//
// Python parity, three points:
//
//   - the four list fallbacks are `x or [default]`, i.e. PYTHON TRUTHINESS, not
//     `is None`. An EXPLICIT EMPTY LIST therefore also falls back to the
//     default: `scan_types=[]` yields ["sast","sca","secrets","config"], and
//     `exclude_paths=[]` yields the four-entry default. There is no way to ask
//     for "no exclusions" through this reasoner. Reproduced.
//   - `include_paths` has NO fallback: it is forwarded as-is, so None stays
//     None (scan everything) and [] stays [] (an empty include filter).
//   - `enable_dast=enable_dast` is passed to a model that has NO `enable_dast`
//     FIELD — AuditInput declares `dast_enabled`. pydantic's default
//     `extra="ignore"` DROPS it silently, so `dast_enabled` is False for every
//     request no matter what the caller sends. VERIFIED on the repo's own
//     interpreter (`AuditInput(repo_url="x", enable_dast=True).dast_enabled` is
//     False, and the instance has no `enable_dast` attribute). This is a live
//     Python bug — the reasoner's `enable_dast` parameter is inert — and it is
//     reproduced rather than fixed: DastEnabled is left at the pydantic default.
//
// The five fields audit() does not pass at all (dast_enabled, repo_urls,
// monitoring_mode, baseline_path, custom_policies) keep their pydantic
// defaults, which is what starting from schemas.NewAuditInput() gives.
func (a AuditRequest) ToAuditInput() schemas.AuditInput {
	in := schemas.NewAuditInput()
	in.RepoURL = a.RepoURL
	in.Depth = a.Depth
	in.Branch = a.Branch
	in.CommitSha = a.CommitSha
	in.BaseCommitSha = a.BaseCommitSha
	in.SeverityThreshold = a.SeverityThreshold
	in.ScanTypes = orDefault(a.ScanTypes, []string{"sast", "sca", "secrets", "config"})
	in.OutputFormats = orDefault(a.OutputFormats, []string{"json"})
	in.ComplianceFrameworks = orDefault(a.ComplianceFrameworks, []string{})
	in.MaxCostUsd = a.MaxCostUsd
	in.MaxProvers = a.MaxProvers
	in.MaxDurationSeconds = a.MaxDurationSeconds
	in.IncludePaths = a.IncludePaths
	in.ExcludePaths = orDefault(a.ExcludePaths, []string{"tests/", "vendor/", "node_modules/", ".git/"})
	in.IsPr = a.IsPr
	in.PrID = a.PrID
	in.PostPrComments = a.PostPrComments
	in.FailOnFindings = a.FailOnFindings
	// in.DastEnabled deliberately untouched — see the doc comment.
	return in
}

// bindAuditRequest is the `audit` reasoner's input layer, in Python's order:
//
//	validated = self._validate_handler_input(body, input_fields)   # SDK
//	audit_input = AuditInput(**validated)                          # pydantic
//
// `audit` is registered on the Agent rather than on the reasoner router
// (register.go), so it does not get the router's automatic wrapper — but it is
// the same layer and the same 34-reasoner surface, so the SDK-level validation
// runs here explicitly. It is what turns `{"is_pr": "yes"}` into true and
// `{"repo_url": 5}` into "5" instead of a bind error, and what rejects an
// explicit null on a required parameter.
func bindAuditRequest(input map[string]any) (AuditRequest, error) {
	validated, err := reasoners.ValidateHandlerInput(reasoners.NameAudit, input)
	if err != nil {
		return AuditRequest{}, err
	}
	return afx.Bind[AuditRequest](validated)
}

// orDefault is Python's `value or default` for a list: an empty (or nil) slice
// is falsy and yields the default.
func orDefault(value, def []string) []string {
	if len(value) == 0 {
		return def
	}
	return value
}

// auditHandler ports the `audit(...)` reasoner (app.py:123-231).
//
// The Python shape, and the shape reproduced here:
//
//	audit_input = AuditInput(...)                # bind
//	orchestrator = AuditOrchestrator(app, input) # OUTSIDE the try
//	repo_path = _resolve_repo(repo_url)          # OUTSIDE the try
//	orchestrator.repo_path = Path(repo_path)
//	orchestrator.checkpoint_dir = repo_path/".sec-af"
//	try:
//	    <resume branch> | <four-call pipeline>
//	except ValueError as exc:  400 {"error": str(exc)}
//	except Exception as exc:   note("Audit pipeline failed: ..."); 500 {"error": "audit execution failed: ..."}
//	return result.model_dump()
//
// Construction happens BEFORE resolution, which matters: the orchestrator's
// __init__ resolves SEC_AF_REPO_PATH (or the cwd) and — in PR mode with a base
// commit — runs the git diff analysis against THAT path, not against the
// repository the audit is about. SetRepoPath then overwrites repo_path and
// checkpoint_dir without recomputing self.config, so AuditConfig.repo_path also
// keeps the constructor's value. All three quirks are inherited from Python.
func (n *Node) auditHandler(ctx context.Context, input map[string]any) (any, error) {
	req, err := bindAuditRequest(input)
	if err != nil {
		var handlerInput *reasoners.HandlerInputError
		if errors.As(err, &handlerInput) {
			// Python's endpoint rejects the body BEFORE the handler runs, with
			// JSONResponse(422, ...). See reasoners.ValidateHandlerInput.
			return nil, reasoners.HandlerInputExecuteError(err)
		}
		// What is left is an afx.Bind failure, i.e. the pydantic half:
		// `AuditInput(**validated)` at app.py:146, which is raised OUTSIDE
		// audit()'s try and therefore reaches FastAPI as a generic 500. The Go
		// port answers 400 — the closest node-level bad-input signal the SDK
		// exposes for a malformed body — rather than reproducing a status that
		// tells the caller nothing. PRE-EXISTING and unrelated to the input
		// layer above, which now answers Python's own 422.
		return nil, &agent.ExecuteError{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}

	auditInput := req.ToAuditInput()

	orchestrator, err := n.newOrchestrator(ctx, n.auditApp, auditInput)
	if err != nil {
		// Python parity: AuditConfig.from_input raises ValueError("'x' is not a
		// valid DepthProfile") here, OUTSIDE the try, so FastAPI answers with a
		// generic 500 — not the 400 the ValueError branch would give. Reproduced
		// as a 500; the message is surfaced (Python hides it behind FastAPI's
		// generic body) because a silent 500 is undebuggable and the status code
		// — the part a client branches on — is identical. See IsBadInput.
		return nil, &agent.ExecuteError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}

	repoPath, err := n.resolveRepo(ctx, req.RepoURL)
	if err != nil {
		// Python parity: _resolve_repo's ValueError("git clone failed: ...") is
		// also raised outside the try -> generic 500. Same reasoning as above.
		return nil, &agent.ExecuteError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
	}
	orchestrator.SetRepoPath(repoPath)

	result, err := n.runAudit(ctx, orchestrator, req, repoPath)
	if err != nil {
		if IsBadInput(err) {
			// `except ValueError` -> 400 with the RAW message, no note.
			return nil, &agent.ExecuteError{StatusCode: http.StatusBadRequest, Message: err.Error()}
		}
		// `except Exception` -> stdout diagnostic, note, then 500 with the
		// prefix, in that order (app.py:224-230).
		//
		// Python parity: `print(f"AUDIT ERROR: {exc}\n{tb}", flush=True)`. The
		// first line is byte-identical; the traceback that follows it has no Go
		// equivalent (an error value carries no stack, and the panic-style stack
		// available here would be the handler's, not the failure's), so the line
		// is emitted alone. The same operator-facing convention harnessx.Extract
		// follows for `[agent] HARNESS ERROR: ...`.
		fmt.Printf("AUDIT ERROR: %s\n", err)
		n.auditApp.Note(ctx, "Audit pipeline failed: "+err.Error(), "audit", "error")
		return nil, &agent.ExecuteError{
			StatusCode: http.StatusInternalServerError,
			Message:    "audit execution failed: " + err.Error(),
		}
	}

	// Python returns `result.model_dump()`; SecurityAuditResult marshals to the
	// identical snake_case key set, so returning the struct yields the same JSON.
	return result, nil
}

// runAudit is the body of audit()'s `try:` block — everything whose failure the
// 400/500 mapping applies to.
func (n *Node) runAudit(
	ctx context.Context,
	orchestrator *orch.AuditOrchestrator,
	req AuditRequest,
	repoPath string,
) (schemas.SecurityAuditResult, error) {
	// `if isinstance(resume_from_checkpoint, str) and resume_from_checkpoint.strip():`
	// — a whitespace-only value is falsy and takes the full-pipeline branch.
	if req.ResumeFromCheckpoint != nil && strings.TrimSpace(*req.ResumeFromCheckpoint) != "" {
		return orchestrator.RunFromCheckpoint(ctx, *req.ResumeFromCheckpoint)
	}

	app := n.auditApp
	nodeID := n.callNodeID

	app.Note(ctx, "Starting SEC-AF audit pipeline", "audit", "start")
	started := nowMonotonic()

	// --- recon_phase --------------------------------------------------------
	reconDict, err := callMap(ctx, app, nodeID, reasoners.NameReconPhase, map[string]any{
		"repo_path": repoPath,
		"depth":     req.Depth,
	})
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	recon, err := phases.BindReconResult(reconDict)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	recon.ReconDurationSeconds = nowMonotonic().Sub(started).Seconds()
	if err := orchestrator.WriteCheckpoint(orch.PhaseRecon, recon); err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	// --- hunt_phase ---------------------------------------------------------
	// Python parity: the kwarg is `recon_context=recon_dict` — the RAW payload
	// map returned by recon_phase, NOT recon.model_dump(). The two differ:
	// recon_duration_seconds was just stamped on the MODEL and is still 0.0 in
	// the dict that goes over the wire.
	huntDict, err := callMap(ctx, app, nodeID, reasoners.NameHuntPhase, map[string]any{
		"repo_path":     repoPath,
		"recon_context": reconDict,
		"depth":         req.Depth,
	})
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	hunt, err := phases.BindHuntResult(huntDict)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	// Python: `time.monotonic() - started - recon.recon_duration_seconds`, i.e.
	// the hunt's own share of the elapsed time.
	hunt.HuntDurationSeconds = nowMonotonic().Sub(started).Seconds() - recon.ReconDurationSeconds
	if err := orchestrator.WriteCheckpoint(orch.PhaseHunt, hunt); err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	// --- prove_phase --------------------------------------------------------
	// Python parity: here the kwarg IS `hunt.model_dump()` (the model, with the
	// duration stamped), unlike recon_context above.
	huntDump, err := afx.ToMap(hunt)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	proveDict, err := callMap(ctx, app, nodeID, reasoners.NameProvePhase, map[string]any{
		"repo_path":   repoPath,
		"hunt_result": huntDump,
		"depth":       req.Depth,
		"max_provers": req.MaxProvers,
	})
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	// Python: `prove_dict["verified"]` — a SUBSCRIPT, so a payload without the
	// key raises KeyError (an Exception, not a ValueError => 500).
	verifiedRaw, ok := proveDict["verified"]
	if !ok {
		return schemas.SecurityAuditResult{}, &missingKeyError{Key: "verified", Source: reasoners.NameProvePhase}
	}
	verified, err := bindVerifiedList(verifiedRaw)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	orchestrator.FindingsNotVerified = mapInt(proveDict, "not_verified", 0)
	// Python: `prove_dict.get("drop_summary", {"demoted_total": 0, "by_reason": {}, "findings": []})`
	// (app.py:205-208) — a `.get`, so the default fires ONLY when the key is
	// ABSENT. A key that is PRESENT with an odd value (a JSON null, a string, a
	// list, a number) is threaded through verbatim and surfaces in the audit
	// result's `metadata.prove_drop_summary`, which is `dict[str, object]` and
	// accepts anything. Testing the VALUE's type here instead — as an earlier
	// draft did — replaced a caller-visible `null` with the default object.
	//
	// afx.WireNumbers restores the int-vs-float split CPython's json.loads
	// makes: the summary is stored UNTYPED and re-serialised into
	// `metadata["prove_drop_summary"]`, where a float64 2 would print "2.0"
	// against Python's "2".
	if summary, present := proveDict["drop_summary"]; present {
		orchestrator.ProveDropSummary = afx.WireNumbers(summary)
	} else {
		orchestrator.ProveDropSummary = orch.NewDropSummary()
	}

	if err := orchestrator.WriteCheckpoint(orch.PhaseProve, verified); err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	// --- remediation_phase --------------------------------------------------
	verifiedDumps := make([]any, 0, len(verified))
	for i := range verified {
		dump, dumpErr := afx.ToMap(verified[i])
		if dumpErr != nil {
			return schemas.SecurityAuditResult{}, dumpErr
		}
		verifiedDumps = append(verifiedDumps, dump)
	}
	remediationDict, err := callMap(ctx, app, nodeID, reasoners.NameRemediationPhase, map[string]any{
		"repo_path":         repoPath,
		"verified_findings": verifiedDumps,
	})
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}
	remediatedRaw, ok := remediationDict["verified"]
	if !ok {
		return schemas.SecurityAuditResult{}, &missingKeyError{Key: "verified", Source: reasoners.NameRemediationPhase}
	}
	verified, err = bindVerifiedList(remediatedRaw)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	// Python: total_selected + len(hunt.strategies_run) + 3. The "+3" counts the
	// three phase reasoners that are not per-finding fan-outs (recon, hunt,
	// prove); remediation is not counted, and neither is `audit` itself.
	orchestrator.SetAgentInvocations(mapInt(proveDict, "total_selected", 0) + len(hunt.StrategiesRun) + 3)

	result, err := orchestrator.GenerateOutput(ctx, recon, hunt, verified)
	if err != nil {
		return schemas.SecurityAuditResult{}, err
	}

	app.Note(ctx, "SEC-AF audit complete", "audit", "complete")
	return result, nil
}

// callMap is app.py's
//
//	raw = await app.call(f"{NODE_ID}.{name}", **kwargs)
//	payload = _as_dict(_unwrap(raw, name), name)
//
// app.py declares its own byte-identical copies of _unwrap/_as_dict alongside
// reasoners/phases.py's; afx owns the single Go implementation.
func callMap(ctx context.Context, app appx.Caller, nodeID, name string, input map[string]any) (map[string]any, error) {
	raw, err := app.Call(ctx, nodeID+"."+name, input)
	if err != nil {
		return nil, err
	}
	payload, err := afx.Unwrap(raw, name)
	if err != nil {
		return nil, err
	}
	return afx.AsMap(payload, name)
}

// bindVerifiedList is `[VerifiedFinding.model_validate(v) for v in payload]`
// (app.py:201 and :213).
//
// The comprehension has TWO distinct failure modes, and Python maps them to
// DIFFERENT audit responses, so the port keeps them apart:
//
//   - the payload is not ITERABLE -> TypeError, an Exception but not a
//     ValueError, so audit()'s `except Exception` answers 500. str(exc) is
//     `'int' object is not iterable` (VERIFIED on the pinned interpreter for
//     int/float/bool/NoneType), which notIterableError reproduces.
//   - the payload iterates but an ELEMENT is not a mapping ->
//     `VerifiedFinding.model_validate(5)` raises a pydantic ValidationError,
//     which SUBCLASSES ValueError, so audit() answers 400 with
//     `Input should be a valid dictionary or instance of VerifiedFinding`
//     (VERIFIED: one `model_type` error, `isinstance(exc, ValueError)` True).
//     A *phases.ValidationError is what IsBadInput routes to that branch.
//
// Iterability follows Python, not Go: a STRING iterates its characters and a
// DICT iterates its keys, so both reach the element branch (and an empty dict
// or empty string yields an empty list, not an error) — only the scalars and
// None are "not iterable".
func bindVerifiedList(payload any) ([]schemas.VerifiedFinding, error) {
	items, ok := pyIterate(payload)
	if !ok {
		return nil, &notIterableError{Got: afx.PyTypeName(payload)}
	}
	out := make([]schemas.VerifiedFinding, 0, len(items))
	for _, item := range items {
		row, isMap := item.(map[string]any)
		if !isMap {
			return nil, &phases.ValidationError{
				Model:  "VerifiedFinding",
				Errors: []string{"Input should be a valid dictionary or instance of VerifiedFinding"},
			}
		}
		finding, err := phases.BindVerifiedFinding(row)
		if err != nil {
			return nil, err
		}
		out = append(out, finding)
	}
	return out, nil
}

// pyIterate is `list(x)` for the JSON value kinds a `.call` payload can hold:
// a list yields its elements, a string its CHARACTERS, a dict its KEYS, and
// everything else (numbers, booleans, None) is not iterable.
func pyIterate(payload any) ([]any, bool) {
	switch v := payload.(type) {
	case []any:
		return v, true
	case string:
		out := make([]any, 0, len(v))
		for _, r := range v {
			out = append(out, string(r))
		}
		return out, true
	case map[string]any:
		// Python iterates a dict in INSERTION order, which a decoded Go map
		// does not carry; sorting keeps the walk deterministic. The order is
		// unobservable here anyway — every key is a string, so whichever comes
		// first fails the element branch identically.
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make([]any, 0, len(keys))
		for _, key := range keys {
			out = append(out, key)
		}
		return out, true
	}
	return nil, false
}

// mapInt is `payload.get(key, def)` coerced to an int.
//
// A JSON number arrives as float64 through the control plane and as an int when
// a Go caller built the map in process, so both are accepted; anything else
// (including an absent key) yields def. Python would happily store a float in
// findings_not_verified / agent_invocations; the Go fields are typed int, and
// every producer of these keys emits an integer.
func mapInt(payload map[string]any, key string, def int) int {
	switch v := payload[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	}
	return def
}

// missingKeyError stands in for Python's KeyError on `prove_dict["verified"]`
// (app.py:201) and `remediation_dict["verified"]` (app.py:213).
//
// The TEXT is `str(exc)`, not `repr(exc)`: app.py:229-230 interpolates the
// exception into `f"Audit pipeline failed: {exc}"` and
// `f"audit execution failed: {exc}"`, and `str(KeyError('verified'))` is
// `'verified'` — the repr of the KEY, with quotes and with no class-name
// prefix (VERIFIED on the pinned interpreter). Source is kept as a field
// because it is useful in tests and logs, but it must not appear in Error().
// Same rule as prove.ErrChainTagsNotASet and the phases select_strategy gate.
type missingKeyError struct {
	Key    string
	Source string
}

func (e *missingKeyError) Error() string {
	return "'" + e.Key + "'"
}

// notIterableError stands in for the TypeError a non-iterable `verified`
// produces. `str(exc)` is `'int' object is not iterable` — again no class-name
// prefix (VERIFIED for int, float, bool and NoneType).
//
// Documented residual, inherited from afx.PyTypeName: Go's encoding/json
// decodes every JSON number to float64, so an integral payload says "float"
// where CPython's json.loads would have said "int".
type notIterableError struct{ Got string }

func (e *notIterableError) Error() string {
	return "'" + e.Got + "' object is not iterable"
}

// The `audit` reasoner's declared input schema is NOT written out here. It
// comes from the same capture of the live Python node that the router
// reasoners' schemas come from — reasoners.InputSchema(reasoners.NameAudit),
// see internal/reasoners/input_schemas.go — and register.go attaches it.
//
// A hand-written transcription of the app.py signature used to live at this
// spot. It was dropped because it was materially RICHER than what Python
// actually publishes, and therefore wrong for a port whose contract is "same
// discovery payload":
//
//   - it typed the nullable parameters by their base type
//     (`commit_sha: {"type":"string"}`, `scan_types: {"type":"array",...}`),
//     while Python reports `{"type":"object"}` for every `X | None` — its
//     Union branch never fires for a PEP 604 union;
//   - it carried `default` and `description` keywords, which
//     `_types_to_json_schema` does not emit at all;
//   - it set `additionalProperties: true` at the top level, which Python only
//     emits for `dict[str, Any]`-typed PROPERTIES, never for the schema root.
//
// The Go-side defaults those keywords documented are still enforced — by
// AuditRequest.UnmarshalJSON and ToAuditInput, which are what actually bind the
// request — so nothing is lost but the divergent advertisement.
