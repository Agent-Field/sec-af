package recontext

// Parity tests for the two hint tables ported from
// src/sec_af/agents/hunt/_language_hints.py and _framework_hints.py.
//
// The input vectors below are the SAME literals go/scripts/gen_golden.py uses
// (LANGUAGE_HINT_CASES / FRAMEWORK_HINT_CASES); if the two drift apart the
// golden comparison fails, which is the intended alarm.

import "testing"

// languageHintCases mirrors gen_golden.py's LANGUAGE_HINT_CASES.
var languageHintCases = []struct {
	name      string
	languages []string
}{
	{"empty", []string{}},
	{"unknown_only", []string{"Rust", "haskell"}},
	{"single", []string{"Python"}},
	{"mixed_case_and_repeat", []string{"Python", "python", "JavaScript", "Rust", "GO"}},
	{"all_known", []string{"python", "javascript", "typescript", "go", "java", "ruby", "csharp"}},
}

// frameworkHintCases mirrors gen_golden.py's FRAMEWORK_HINT_CASES.
var frameworkHintCases = []struct {
	name       string
	frameworks []string
}{
	{"empty", []string{}},
	{"unknown_only", []string{"hanami", "phoenix"}},
	{"aliases", []string{"Next", "next.js", "NEXTJS", "Spring Boot", "spring-boot", "ASP.NET Core"}},
	{"padded", []string{"  React  ", "\tvue\n", "Django"}},
	{"all_known", []string{
		"django", "flask", "fastapi", "express", "nextjs",
		"spring", "rails", "aspnet", "react", "vue", "angular",
	}},
}

// TestGetLanguageHintsMatchesPython pins the whole LANGUAGE_PATTERNS table
// through its rendering — every sink, safe pattern, do-not-flag entry and
// framework note of all seven languages appears in the all_known golden.
//
// The mixed_case_and_repeat case is the interesting one: get_language_hints
// does NOT deduplicate, so "Python" and "python" each emit a PYTHON section,
// and "Rust" (no table entry) contributes nothing.
func TestGetLanguageHintsMatchesPython(t *testing.T) {
	for _, tc := range languageHintCases {
		t.Run(tc.name, func(t *testing.T) {
			want := golden(t, "language_hints_"+tc.name+".txt")
			if got := GetLanguageHints(tc.languages); got != want {
				t.Errorf("GetLanguageHints(%v) mismatch:\n%s", tc.languages, firstDiff(want, got))
			}
		})
	}
}

// TestGetFrameworkHintsMatchesPython pins FRAMEWORK_PATTERNS and the alias
// table. The aliases case proves Next/next.js/NEXTJS collapse to ONE NEXTJS
// section and Spring Boot/spring-boot to one SPRING; the padded case proves
// `.strip().lower()` runs before the alias lookup.
func TestGetFrameworkHintsMatchesPython(t *testing.T) {
	for _, tc := range frameworkHintCases {
		t.Run(tc.name, func(t *testing.T) {
			want := golden(t, "framework_hints_"+tc.name+".txt")
			if got := GetFrameworkHints(tc.frameworks); got != want {
				t.Errorf("GetFrameworkHints(%v) mismatch:\n%s", tc.frameworks, firstDiff(want, got))
			}
		})
	}
}

// TestHintsForContextWrappers pins language_hints_for_context /
// framework_hints_for_context, which are the functions every hunter actually
// calls: they feed the ReconResult's own language and framework lists — which
// in the fixture are deliberately messy ("Python" twice, "  React  " padded,
// "next.js" and "NEXT" aliasing to the same entry, "unknown-fw" unmatched).
func TestHintsForContextWrappers(t *testing.T) {
	recon := loadReconFixture(t)

	if got, want := LanguageHintsForContext(recon), golden(t, "language_hints_for_context.txt"); got != want {
		t.Errorf("LanguageHintsForContext mismatch:\n%s", firstDiff(want, got))
	}
	if got, want := FrameworkHintsForContext(recon), golden(t, "framework_hints_for_context.txt"); got != want {
		t.Errorf("FrameworkHintsForContext mismatch:\n%s", firstDiff(want, got))
	}
}

// TestHintTableKeys guards the table membership itself, so a dropped or
// misspelled key is caught even when no golden covers it.
func TestHintTableKeys(t *testing.T) {
	wantLanguages := []string{"python", "javascript", "typescript", "go", "java", "ruby", "csharp"}
	if len(LanguagePatterns) != len(wantLanguages) {
		t.Errorf("LanguagePatterns has %d entries, want %d", len(LanguagePatterns), len(wantLanguages))
	}
	for _, key := range wantLanguages {
		if _, ok := LanguagePatterns[key]; !ok {
			t.Errorf("LanguagePatterns missing %q", key)
		}
	}

	wantFrameworks := []string{
		"django", "flask", "fastapi", "express", "nextjs",
		"spring", "rails", "aspnet", "react", "vue", "angular",
	}
	if len(FrameworkPatterns) != len(wantFrameworks) {
		t.Errorf("FrameworkPatterns has %d entries, want %d", len(FrameworkPatterns), len(wantFrameworks))
	}
	for _, key := range wantFrameworks {
		if _, ok := FrameworkPatterns[key]; !ok {
			t.Errorf("FrameworkPatterns missing %q", key)
		}
	}
}

// TestNormalizeFramework pins _normalize_framework's alias table one entry at a
// time, including the identity case for a name that is not an alias.
func TestNormalizeFramework(t *testing.T) {
	cases := map[string]string{
		"next":          "nextjs",
		"Next":          "nextjs",
		"next.js":       "nextjs",
		"  NEXT.JS  ":   "nextjs",
		"springboot":    "spring",
		"spring-boot":   "spring",
		"spring boot":   "spring",
		"asp.net":       "aspnet",
		"asp.net core":  "aspnet",
		"aspnetcore":    "aspnet",
		"asp net":       "aspnet",
		"ruby on rails": "rails",
		"django":        "django",
		"Django":        "django",
		"unknown-fw":    "unknown-fw",
		"":              "",
	}
	for in, want := range cases {
		if got := normalizeFramework(in); got != want {
			t.Errorf("normalizeFramework(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNoHintsFallbacks pins the two "nothing matched" sentences, which are the
// literal strings the prompt templates end up carrying for an unrecognized
// stack.
func TestNoHintsFallbacks(t *testing.T) {
	if got, want := GetLanguageHints(nil), "No language-specific hints available for detected languages."; got != want {
		t.Errorf("GetLanguageHints(nil) = %q, want %q", got, want)
	}
	if got, want := GetFrameworkHints(nil), "No framework-specific hints available for detected frameworks."; got != want {
		t.Errorf("GetFrameworkHints(nil) = %q, want %q", got, want)
	}
}
