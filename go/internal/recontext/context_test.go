package recontext

// Parity tests for src/sec_af/context.py.
//
// Every expectation is a COMMITTED GOLDEN produced by running the real Python
// function over testdata/recon_fixture.json:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py
//
// The fixture is deliberately oversized — 19 modules, 17 entry points, 20 API
// endpoints, 20 data flows, 18 sinks, 18 CVEs, 17 secrets, 16 misconfigs, 16
// crypto entries — so that every _MAX_PRIMARY_ITEMS (15) and
// _MAX_SECONDARY_ITEMS (10) truncation fires, every stable-sort tie is
// exercised, and the "N total, showing top M" counters differ from each other.
// It also carries the awkward cases on purpose: None routes, None
// auth_required/rate_limited/reachable/is_weak, a CVE with no CVSS and no EPSS,
// empty enforcement/protects_against lists, empty-string security signals (which
// _limit's truthiness filter must DROP before counting), a misconfig with
// line=None and one with line=0, duplicate SBOM entries (which the set
// comprehension must collapse), and repeated/aliased/padded language and
// framework names.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

func loadReconFixture(t *testing.T) schemas.ReconResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "recon_fixture.json"))
	if err != nil {
		t.Fatalf("read recon_fixture.json: %v", err)
	}
	var recon schemas.ReconResult
	if err := json.Unmarshal(raw, &recon); err != nil {
		t.Fatalf("unmarshal ReconResult: %v", err)
	}
	return recon
}

func golden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with go/scripts/gen_golden.py)", name, err)
	}
	return string(raw)
}

func goldenJSON(t *testing.T, name string, dest any) {
	t.Helper()
	if err := json.Unmarshal([]byte(golden(t, name)), dest); err != nil {
		t.Fatalf("parse golden %s: %v", name, err)
	}
}

// firstDiff points at the first differing line of two prompt-sized strings.
func firstDiff(want, got string) string {
	wantLines, gotLines := splitLines(want), splitLines(got)
	n := len(wantLines)
	if len(gotLines) < n {
		n = len(gotLines)
	}
	for i := 0; i < n; i++ {
		if wantLines[i] != gotLines[i] {
			w, _ := json.Marshal(wantLines[i])
			g, _ := json.Marshal(gotLines[i])
			return "first difference at line " + itoa(i+1) + "\n want: " + string(w) + "\n  got: " + string(g)
		}
	}
	if len(wantLines) != len(gotLines) {
		return "line counts differ: want " + itoa(len(wantLines)) + ", got " + itoa(len(gotLines))
	}
	return "(no line differs; check trailing bytes)"
}

func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestReconContextBuildersMatchPython is the headline parity assertion: all
// eight strategy projections plus the generic fallback, byte for byte.
func TestReconContextBuildersMatchPython(t *testing.T) {
	recon := loadReconFixture(t)

	cases := []struct {
		golden  string
		builder func(schemas.ReconResult) string
	}{
		{"injection.txt", ReconContextForInjection},
		{"auth.txt", ReconContextForAuth},
		{"crypto.txt", ReconContextForCrypto},
		{"data_exposure.txt", ReconContextForDataExposure},
		{"config_secrets.txt", ReconContextForConfigSecrets},
		{"supply_chain.txt", ReconContextForSupplyChain},
		{"api_security.txt", ReconContextForAPISecurity},
		{"logic.txt", ReconContextForLogic},
		{"generic.txt", ReconContextGeneric},
	}

	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			want := golden(t, tc.golden)
			if got := tc.builder(recon); got != want {
				t.Errorf("%s mismatch:\n%s", tc.golden, firstDiff(want, got))
			}
		})
	}
}

// TestGetContextForStrategyDispatch pins which builder every HuntStrategy value
// lands on. The golden stores the SHA-256 of the rendered text rather than the
// text itself (13 strategies x ~5 KB would bloat testdata), which is enough to
// catch a mis-wired dispatch: a strategy routed to the wrong builder produces a
// different digest, and the builders themselves are pinned byte-for-byte above.
//
// Python parity: xss, ssrf and dos have STRATEGY_CONTEXT_MAP entries but no
// builder, so they must hash to the same value as the generic summary; and
// business_logic (a.k.a. LOGIC_BUGS) must hash to recon_context_for_logic's.
func TestGetContextForStrategyDispatch(t *testing.T) {
	recon := loadReconFixture(t)

	var want map[string]string
	goldenJSON(t, "strategy_dispatch.json", &want)

	if len(want) != len(schemas.AllHuntStrategies) {
		t.Fatalf("golden covers %d strategies, schemas.AllHuntStrategies has %d",
			len(want), len(schemas.AllHuntStrategies))
	}

	for _, strategy := range schemas.AllHuntStrategies {
		value := string(strategy)
		sum := sha256.Sum256([]byte(GetContextForStrategy(strategy, recon)))
		got := hex.EncodeToString(sum[:])
		if want[value] != got {
			t.Errorf("GetContextForStrategy(%q) digest = %s, want %s", value, got, want[value])
		}
	}

	// The three mapped-but-builderless strategies fall through to the generic
	// summary, and business_logic does not.
	genericSum := sha256.Sum256([]byte(ReconContextGeneric(recon)))
	generic := hex.EncodeToString(genericSum[:])
	for _, value := range []string{"xss", "ssrf", "dos", "python_specific", "javascript_specific"} {
		if want[value] != generic {
			t.Errorf("strategy %q should render the generic summary", value)
		}
	}
	logicSum := sha256.Sum256([]byte(ReconContextForLogic(recon)))
	if want["business_logic"] != hex.EncodeToString(logicSum[:]) {
		t.Error("business_logic should render recon_context_for_logic")
	}
	// The LOGIC_BUGS alias is the same constant, so it must dispatch identically.
	if GetContextForStrategy(schemas.HuntStrategyLogicBugs, recon) != ReconContextForLogic(recon) {
		t.Error("HuntStrategy.LOGIC_BUGS must alias BUSINESS_LOGIC")
	}
}

// TestPruneReconForStrategyKeys pins the surviving key set for every strategy
// value plus a miss and the empty string, against
// `sorted(prune_recon_for_strategy(recon, s))` in Python.
func TestPruneReconForStrategyKeys(t *testing.T) {
	recon := loadReconFixture(t)

	var want map[string][]string
	goldenJSON(t, "prune_keys.json", &want)

	for strategy, wantKeys := range want {
		pruned, err := PruneReconForStrategy(recon, strategy)
		if err != nil {
			t.Fatalf("PruneReconForStrategy(%q): %v", strategy, err)
		}
		gotKeys := make([]string, 0, len(pruned))
		for key := range pruned {
			gotKeys = append(gotKeys, key)
		}
		sort.Strings(gotKeys)
		if len(gotKeys) != len(wantKeys) {
			t.Errorf("strategy %q: keys = %v, want %v", strategy, gotKeys, wantKeys)
			continue
		}
		for i := range gotKeys {
			if gotKeys[i] != wantKeys[i] {
				t.Errorf("strategy %q: keys = %v, want %v", strategy, gotKeys, wantKeys)
				break
			}
		}
	}
}

// TestPruneReconForStrategyRendering compares the full pruned document — every
// nested value, not just the key set — with Python's json.dumps of the same
// dict.
//
// The golden is generated with only the TOP LEVEL sorted, because that is
// exactly the document pyfmt.Dumps produces here: the pruned value is a Go map
// (sorted keys — pyfmt's documented deviation) whose values are typed structs
// (declaration order, which is pydantic's model_dump() order). So a byte match
// proves the nested rendering is identical, including int-vs-float spelling
// (cvss_v4_score 10.0 stays "10.0") and every nullable field.
func TestPruneReconForStrategyRendering(t *testing.T) {
	recon := loadReconFixture(t)

	for _, strategy := range []string{"injection", "crypto", "supply_chain", "config_secrets", "unknown_strategy"} {
		t.Run(strategy, func(t *testing.T) {
			pruned, err := PruneReconForStrategy(recon, strategy)
			if err != nil {
				t.Fatalf("PruneReconForStrategy: %v", err)
			}
			want := golden(t, "prune_"+strategy+".json")
			if got := pyfmt.Dumps(pruned, 2); got != want {
				t.Errorf("prune_%s.json mismatch:\n%s", strategy, firstDiff(want, got))
			}
		})
	}
}

// TestStrategyContextMapMatchesPython pins the table itself, so a typo in a
// field name is caught even for a strategy whose pruned golden is not committed.
func TestStrategyContextMapMatchesPython(t *testing.T) {
	want := map[string][]string{
		"injection":      {"architecture", "data_flows", "security_context"},
		"xss":            {"architecture", "data_flows", "security_context"},
		"ssrf":           {"architecture", "data_flows", "security_context"},
		"auth":           {"architecture", "security_context"},
		"crypto":         {"security_context"},
		"dos":            {"architecture", "data_flows"},
		"data_exposure":  {"architecture", "data_flows", "config"},
		"supply_chain":   {"dependencies"},
		"config_secrets": {"config", "architecture"},
		"api_security":   {"architecture", "security_context", "data_flows"},
		"business_logic": {"architecture", "data_flows", "security_context"},
	}
	if len(StrategyContextMap) != len(want) {
		t.Fatalf("StrategyContextMap has %d entries, want %d", len(StrategyContextMap), len(want))
	}
	for key, wantFields := range want {
		gotFields, ok := StrategyContextMap[key]
		if !ok {
			t.Errorf("StrategyContextMap missing %q", key)
			continue
		}
		if len(gotFields) != len(wantFields) {
			t.Errorf("%q: %v, want %v", key, gotFields, wantFields)
			continue
		}
		for i := range wantFields {
			if gotFields[i] != wantFields[i] {
				t.Errorf("%q: %v, want %v", key, gotFields, wantFields)
				break
			}
		}
	}

	wantBase := []string{"languages", "frameworks", "lines_of_code", "file_count"}
	if len(BaseReconFields) != len(wantBase) {
		t.Fatalf("BaseReconFields = %v, want %v", BaseReconFields, wantBase)
	}
	for i := range wantBase {
		if BaseReconFields[i] != wantBase[i] {
			t.Fatalf("BaseReconFields = %v, want %v", BaseReconFields, wantBase)
		}
	}
}

// TestLimitFiltersFalsyBeforeCounting pins _limit's least obvious behavior: the
// truthiness filter runs BEFORE len() is taken, so blanks never appear in the
// "N total" figure.
func TestLimitFiltersFalsyBeforeCounting(t *testing.T) {
	rows, total := limit([]string{"a", "", "b", "", "c"}, 2)
	if total != 3 {
		t.Errorf("total = %d, want 3 (blanks are dropped before counting)", total)
	}
	if len(rows) != 2 || rows[0] != "a" || rows[1] != "b" {
		t.Errorf("rows = %v, want [a b]", rows)
	}

	if got, want := renderList("Title", nil, 5), "Title: none identified in recon."; got != want {
		t.Errorf("empty renderList = %q, want %q", got, want)
	}
	if got, want := renderList("Title", []string{"", ""}, 5), "Title: none identified in recon."; got != want {
		t.Errorf("all-blank renderList = %q, want %q", got, want)
	}
	if got, want := renderList("T", []string{"a", "b"}, 1), "T: 2 total, showing top 1:\n- a"; got != want {
		t.Errorf("truncated renderList = %q, want %q", got, want)
	}
}

// TestEndpointRankKeyIsIdentityTest pins the `is False` semantics: an UNKNOWN
// (None) auth_required ranks with the protected endpoints, not the unprotected
// ones. A truthiness test would sort them together and reorder the prompt.
func TestEndpointRankKeyIsIdentityTest(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		auth, rate *bool
		wantA      int
		wantB      int
	}{
		{&no, &no, 0, 0},
		{&no, &yes, 0, 1},
		{&no, nil, 0, 1},
		{nil, &no, 1, 0},
		{&yes, &yes, 1, 1},
		{nil, nil, 1, 1},
	}
	for _, tc := range cases {
		a, b := endpointRankKey(tc.auth, tc.rate)
		if a != tc.wantA || b != tc.wantB {
			t.Errorf("endpointRankKey(%v, %v) = (%d,%d), want (%d,%d)",
				tc.auth, tc.rate, a, b, tc.wantA, tc.wantB)
		}
	}
}

// TestRankedEndpointsIsStable pins that ties keep recon order — Python's
// sorted() is stable and the prompt's endpoint order is observable output.
func TestRankedEndpointsIsStable(t *testing.T) {
	no := false
	endpoints := []schemas.APIEndpoint{
		{Path: "/a"},                    // rank (1,1)
		{Path: "/b", AuthRequired: &no}, // rank (0,1)
		{Path: "/c"},                    // rank (1,1)
		{Path: "/d", AuthRequired: &no, RateLimited: &no}, // rank (0,0)
		{Path: "/e", AuthRequired: &no},                   // rank (0,1)
	}
	want := []string{"/d", "/b", "/e", "/a", "/c"}
	ranked := rankedEndpoints(endpoints)
	for i, endpoint := range ranked {
		if endpoint.Path != want[i] {
			t.Fatalf("ranked order = %v, want %v", pathsOf(ranked), want)
		}
	}
	// sorted() returns a NEW list; the caller's slice must be untouched.
	if endpoints[0].Path != "/a" {
		t.Error("rankedEndpoints mutated its input")
	}
}

func pathsOf(endpoints []schemas.APIEndpoint) []string {
	out := make([]string, len(endpoints))
	for i, endpoint := range endpoints {
		out[i] = endpoint.Path
	}
	return out
}

// TestCVEPriorityDefaults pins the asymmetry between the reachable rank
// (truthiness — None ranks with False) and the score defaults (an explicit
// `is not None` check, so a missing CVSS sorts BELOW a 0.0 CVSS).
func TestCVEPriorityDefaults(t *testing.T) {
	zero := 0.0
	yes := true

	_, missingCvss, missingEpss, _ := cvePriority(schemas.KnownCVE{})
	if missingCvss != 1.0 || missingEpss != 1.0 {
		t.Errorf("missing scores => (%v,%v), want (1,1) — i.e. -(-1.0)", missingCvss, missingEpss)
	}
	_, zeroCvss, _, _ := cvePriority(schemas.KnownCVE{CvssV4Score: &zero})
	if zeroCvss != 0.0 {
		t.Errorf("cvss 0.0 => %v, want 0", zeroCvss)
	}
	if missingCvss <= zeroCvss {
		t.Error("a CVE with no CVSS must sort after one scored 0.0")
	}

	rankNone, _, _, directNone := cvePriority(schemas.KnownCVE{})
	if rankNone != 1 || directNone != 1 {
		t.Errorf("reachable=None/direct=false => (%d,%d), want (1,1)", rankNone, directNone)
	}
	rankTrue, _, _, directTrue := cvePriority(schemas.KnownCVE{Reachable: &yes, Direct: true})
	if rankTrue != 0 || directTrue != 0 {
		t.Errorf("reachable=True/direct=true => (%d,%d), want (0,0)", rankTrue, directTrue)
	}
}

// TestWeakCryptoFirstIsTruthiness pins that an UNKNOWN is_weak sorts with the
// strong algorithms, and that the sort is stable.
func TestWeakCryptoFirstIsTruthiness(t *testing.T) {
	yes, no := true, false
	usages := []schemas.CryptoUsage{
		{Algorithm: "AES", IsWeak: &no},
		{Algorithm: "MD5", IsWeak: &yes},
		{Algorithm: "ECDSA", IsWeak: nil},
		{Algorithm: "RC4", IsWeak: &yes},
	}
	want := []string{"MD5", "RC4", "AES", "ECDSA"}
	for i, usage := range weakCryptoFirst(usages) {
		if usage.Algorithm != want[i] {
			t.Fatalf("weakCryptoFirst order = %v, want %v", algosOf(weakCryptoFirst(usages)), want)
		}
	}
	if usages[0].Algorithm != "AES" {
		t.Error("weakCryptoFirst mutated its input")
	}
}

func algosOf(usages []schemas.CryptoUsage) []string {
	out := make([]string, len(usages))
	for i, usage := range usages {
		out[i] = usage.Algorithm
	}
	return out
}

// TestInjectionPrefersUnsanitizedFlows pins the `unsanitized or all` fallback:
// with at least one unsanitized flow only those are listed; with none, every
// flow is.
func TestInjectionPrefersUnsanitizedFlows(t *testing.T) {
	recon := schemas.NewReconResult()
	recon.DataFlows.Flows = []schemas.DataFlow{
		{Source: "s1", Sink: "k1", Sanitized: true, Files: []string{}},
		{Source: "s2", Sink: "k2", Sanitized: false, Files: []string{}},
	}
	out := ReconContextForInjection(recon)
	if !contains(out, "s2 -> k2") || contains(out, "s1 -> k1") {
		t.Errorf("with an unsanitized flow present, only it should be listed:\n%s", out)
	}

	recon.DataFlows.Flows = []schemas.DataFlow{
		{Source: "s1", Sink: "k1", Sanitized: true, Files: []string{}},
	}
	out = ReconContextForInjection(recon)
	if !contains(out, "s1 -> k1") {
		t.Errorf("with no unsanitized flow, every flow should be listed:\n%s", out)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestOptionalRenderings pins the f-string spellings of nullable scalars, the
// place a naive port silently swaps "None" for "" or quotes a string.
func TestOptionalRenderings(t *testing.T) {
	yes := true
	num := 1.0
	n := 7
	s := "text"

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"nil bool", str((*bool)(nil)), "None"},
		{"true", str(&yes), "True"},
		{"plain bool", str(false), "False"},
		{"nil float", str((*float64)(nil)), "None"},
		{"integral float", str(&num), "1.0"},
		{"nil int", str((*int)(nil)), "None"},
		{"int", str(&n), "7"},
		{"nil str stays bare", strPtr(nil), "None"},
		{"str stays bare (not quoted)", strPtr(&s), "text"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}

	empty := ""
	if got := orStr(&empty, "n/a"); got != "n/a" {
		t.Errorf("orStr(\"\") = %q, want the fallback (empty strings are falsy)", got)
	}
	zero := 0
	if got := orZeroInt(&zero); got != 0 {
		t.Errorf("orZeroInt(0) = %d, want 0", got)
	}
	if got := orZeroInt(nil); got != 0 {
		t.Errorf("orZeroInt(nil) = %d, want 0", got)
	}
	if got := joinOr(nil, "unknown"); got != "unknown" {
		t.Errorf("joinOr(nil) = %q, want unknown", got)
	}
	if got := joinOr([]string{""}, "unknown"); got != "unknown" {
		t.Errorf("joinOr([\"\"]) = %q, want unknown (the join is empty, hence falsy)", got)
	}
}

// TestPruneReconForStrategyDoesNotAliasBaseFields guards the include-set build:
// a mapped strategy must never drop a base field, and must never leak
// recon_duration_seconds.
func TestPruneReconForStrategyDoesNotAliasBaseFields(t *testing.T) {
	recon := loadReconFixture(t)
	for strategy := range StrategyContextMap {
		pruned, err := PruneReconForStrategy(recon, strategy)
		if err != nil {
			t.Fatalf("PruneReconForStrategy(%q): %v", strategy, err)
		}
		for _, base := range BaseReconFields {
			if _, ok := pruned[base]; !ok {
				t.Errorf("strategy %q dropped base field %q", strategy, base)
			}
		}
		if _, ok := pruned["recon_duration_seconds"]; ok {
			t.Errorf("strategy %q leaked recon_duration_seconds", strategy)
		}
	}
}
