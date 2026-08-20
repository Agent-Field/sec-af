// Package config ports src/sec_af/config.py in full: the depth profiles, the
// budget thresholds, the runtime AuditConfig the orchestrator phases consume,
// and the environment-derived AIIntegrationConfig the node hands to the SDK.
//
// Every environment variable is read at CALL time (inside FromEnv /
// ProviderEnv), never at package init, so a t.Setenv in a test is deterministic
// and nothing is frozen at import. That also matches Python, where the values
// come from `Field(default_factory=lambda: os.getenv(...))` — evaluated when the
// model is constructed, which app.py does at import.
package config

import "strings"

// DepthProfile ports config.py DepthProfile — the scan-depth profile
// (DESIGN.md §9). It is a string type so it marshals to and from the same JSON
// values as the Python `class DepthProfile(str, Enum)`.
type DepthProfile string

// The three profiles, with the exact Python enum values.
const (
	DepthQuick    DepthProfile = "quick"
	DepthStandard DepthProfile = "standard"
	DepthThorough DepthProfile = "thorough"
)

// IsValid reports whether d is one of the three declared profiles — the
// membership test `DepthProfile(value)` performs in Python.
func (d DepthProfile) IsValid() bool {
	switch d {
	case DepthQuick, DepthStandard, DepthThorough:
		return true
	}
	return false
}

// String returns the profile's wire value.
func (d DepthProfile) String() string { return string(d) }

// NormalizeDepth ports the _normalize_depth helper that SEC-AF repeats verbatim
// in four modules — src/sec_af/reasoners/phases.py:52,
// agents/recon/__init__.py:62, agents/hunt/__init__.py:73 and
// agents/prove/__init__.py:47:
//
//	def _normalize_depth(depth: str) -> DepthProfile:
//	    try:
//	        return DepthProfile(depth.lower())
//	    except ValueError:
//	        return DepthProfile.STANDARD
//
// Lower-case first, and ANY unrecognised value silently becomes STANDARD. This
// is the LENIENT path used everywhere inside the pipeline; it is deliberately
// NOT what AuditConfig.FromInput does, which uses the strict `DepthProfile(...)`
// constructor and fails on a bad value.
//
// src/sec_af/agents/hunt/business_logic.py:26 declares a fifth copy that accepts
// `str | DepthProfile` and short-circuits when it is already a profile. In Go
// DepthProfile IS a string type, so NormalizeDepth(string(d)) covers both arms
// with the same result.
func NormalizeDepth(depth string) DepthProfile {
	p := DepthProfile(strings.ToLower(depth))
	if p.IsValid() {
		return p
	}
	return DepthStandard
}
