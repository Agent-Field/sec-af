package schemas

// This file ports src/sec_af/schemas/recon.py — the RECON phase schemas
// (DESIGN.md §4.3), both the structured models that flow downstream and the
// FLAT `*Raw` models the harness actually produces.
//
// Python parity: recon.py declares a `DataFlowStep` that is a DIFFERENT model
// from prove.py's `DataFlowStep`. `schemas/__init__.py` re-exports prove's
// under the bare name and recon's as `ReconDataFlowStep`, so Go does the same.

// Module is a module-level architecture element (DESIGN.md §4.3).
//
// Ports schemas/recon.py Module.
type Module struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Language     string   `json:"language"`
	Description  *string  `json:"description"`
	Dependencies []string `json:"dependencies"`
}

// EntryPoint is an executable entry point (HTTP, CLI, event) (DESIGN.md §4.3).
//
// Ports schemas/recon.py EntryPoint.
type EntryPoint struct {
	Kind         string  `json:"kind"`
	Identifier   string  `json:"identifier"`
	FilePath     string  `json:"file_path"`
	Line         int     `json:"line"`
	Method       *string `json:"method"`
	Route        *string `json:"route"`
	AuthRequired *bool   `json:"auth_required"`
}

// TrustBoundary is a trust transition location (DESIGN.md §4.3).
//
// Ports schemas/recon.py TrustBoundary.
type TrustBoundary struct {
	Name        string   `json:"name"`
	SourceZone  string   `json:"source_zone"`
	TargetZone  string   `json:"target_zone"`
	Description string   `json:"description"`
	Enforcement []string `json:"enforcement"`
}

// Service is a service dependency or external integration (DESIGN.md §4.3).
//
// Ports schemas/recon.py Service.
type Service struct {
	Name          string  `json:"name"`
	ServiceType   string  `json:"service_type"`
	Endpoint      *string `json:"endpoint"`
	Purpose       *string `json:"purpose"`
	AuthMechanism *string `json:"auth_mechanism"`
}

// APIEndpoint is one exposed API surface entry (DESIGN.md §4.3).
//
// Ports schemas/recon.py APIEndpoint.
type APIEndpoint struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Handler      string `json:"handler"`
	FilePath     string `json:"file_path"`
	Line         int    `json:"line"`
	AuthRequired *bool  `json:"auth_required"`
	RateLimited  *bool  `json:"rate_limited"`
}

// ArchitectureMap is the architecture mapper output (DESIGN.md §4.3).
//
// Ports schemas/recon.py ArchitectureMap. Seeded (defaults.go): all five list
// fields default to `[]`.
type ArchitectureMap struct {
	AppType         *string         `json:"app_type"`
	Modules         []Module        `json:"modules"`
	EntryPoints     []EntryPoint    `json:"entry_points"`
	TrustBoundaries []TrustBoundary `json:"trust_boundaries"`
	Services        []Service       `json:"services"`
	APISurface      []APIEndpoint   `json:"api_surface"`
}

// ReconDataFlowStep is an intermediate transformation step in a data flow
// (DESIGN.md §4.3).
//
// Ports schemas/recon.py DataFlowStep, which `schemas/__init__.py` re-exports
// as `ReconDataFlowStep` to leave the bare name to prove.py's different model.
// This is the one used by DataFlow.path and RawFinding.data_flow.
type ReconDataFlowStep struct {
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	Component string `json:"component"`
	Operation string `json:"operation"`
}

// SanitizationPoint is a location where tainted data is sanitized
// (DESIGN.md §4.3).
//
// Ports schemas/recon.py SanitizationPoint. Seeded (defaults.go):
// protects_against defaults to `[]`.
type SanitizationPoint struct {
	FilePath         string   `json:"file_path"`
	Line             int      `json:"line"`
	FunctionName     *string  `json:"function_name"`
	SanitizationType string   `json:"sanitization_type"`
	ProtectsAgainst  []string `json:"protects_against"`
}

// Sink is a security-critical sink reached by application data
// (DESIGN.md §4.3).
//
// Ports schemas/recon.py Sink.
type Sink struct {
	SinkType            string  `json:"sink_type"`
	FilePath            string  `json:"file_path"`
	Line                int     `json:"line"`
	FunctionName        *string `json:"function_name"`
	ExploitabilityNotes *string `json:"exploitability_notes"`
}

// DataFlow is one input-to-sink path (DESIGN.md §4.3).
//
// Ports schemas/recon.py DataFlow. Seeded (defaults.go): path and files
// default to `[]`.
type DataFlow struct {
	Source    string              `json:"source"`
	Path      []ReconDataFlowStep `json:"path"`
	Sink      string              `json:"sink"`
	Sanitized bool                `json:"sanitized"`
	Files     []string            `json:"files"`
}

// DataFlowMap is the aggregated data-flow analysis output (DESIGN.md §4.3).
//
// Ports schemas/recon.py DataFlowMap. Seeded (defaults.go): all three list
// fields default to `[]`.
type DataFlowMap struct {
	Flows              []DataFlow          `json:"flows"`
	SanitizationPoints []SanitizationPoint `json:"sanitization_points"`
	Sinks              []Sink              `json:"sinks"`
}

// Dependency is one software bill-of-materials entry (DESIGN.md §4.3).
//
// Ports schemas/recon.py Dependency.
type Dependency struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Ecosystem string  `json:"ecosystem"`
	Direct    bool    `json:"direct"`
	License   *string `json:"license"`
}

// KnownCVE is a known CVE affecting a dependency (DESIGN.md §4.3).
//
// Ports schemas/recon.py KnownCVE.
type KnownCVE struct {
	CveID            string   `json:"cve_id"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     *string  `json:"fixed_version"`
	CvssV4Score      *float64 `json:"cvss_v4_score"`
	EpssScore        *float64 `json:"epss_score"`
	Direct           bool     `json:"direct"`
	Reachable        *bool    `json:"reachable"`
}

// OutdatedDep is a dependency that lags behind the latest available version
// (DESIGN.md §4.3).
//
// Ports schemas/recon.py OutdatedDep.
type OutdatedDep struct {
	Package        string `json:"package"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	Direct         bool   `json:"direct"`
}

// DependencyReport is the dependency auditor output (DESIGN.md §4.3).
//
// Ports schemas/recon.py DependencyReport. Seeded (defaults.go): sbom,
// known_cves and outdated default to `[]`.
type DependencyReport struct {
	Sbom            []Dependency  `json:"sbom"`
	KnownCves       []KnownCVE    `json:"known_cves"`
	Outdated        []OutdatedDep `json:"outdated"`
	DirectCount     int           `json:"direct_count"`
	TransitiveCount int           `json:"transitive_count"`
}

// SecretFinding is a discovered hardcoded secret or credential
// (DESIGN.md §4.3).
//
// Ports schemas/recon.py SecretFinding. Seeded (defaults.go): ID gets a fresh
// uuid4 from NewSecretFinding.
type SecretFinding struct {
	ID          string `json:"id"`
	SecretType  string `json:"secret_type"`
	FilePath    string `json:"file_path"`
	Line        int    `json:"line"`
	Match       string `json:"match"`
	Confidence  string `json:"confidence"`
	IsTestValue *bool  `json:"is_test_value"`
}

// MisconfigFinding is an insecure configuration finding (DESIGN.md §4.3).
//
// Ports schemas/recon.py MisconfigFinding. Seeded (defaults.go): ID gets a
// fresh uuid4 from NewMisconfigFinding.
type MisconfigFinding struct {
	ID          string  `json:"id"`
	Category    string  `json:"category"`
	FilePath    string  `json:"file_path"`
	Line        *int    `json:"line"`
	Key         *string `json:"key"`
	Value       *string `json:"value"`
	Risk        string  `json:"risk"`
	Remediation *string `json:"remediation"`
}

// ConfigReport is the config scanner output (DESIGN.md §4.3).
//
// Ports schemas/recon.py ConfigReport. Seeded (defaults.go): secrets and
// misconfigs default to `[]`.
type ConfigReport struct {
	Secrets    []SecretFinding    `json:"secrets"`
	Misconfigs []MisconfigFinding `json:"misconfigs"`
}

// CryptoUsage is one cryptography usage profile entry (DESIGN.md §4.3).
//
// Ports schemas/recon.py CryptoUsage.
type CryptoUsage struct {
	Algorithm    string  `json:"algorithm"`
	KeySize      *int    `json:"key_size"`
	Mode         *string `json:"mode"`
	UsageContext *string `json:"usage_context"`
	IsWeak       *bool   `json:"is_weak"`
}

// SecurityContext is the security context profiler output (DESIGN.md §4.3).
//
// Ports schemas/recon.py SecurityContext. Seeded (defaults.go): the four list
// fields default to `[]`.
type SecurityContext struct {
	AuthModel         string        `json:"auth_model"`
	AuthDetails       string        `json:"auth_details"`
	CryptoUsage       []CryptoUsage `json:"crypto_usage"`
	FrameworkSecurity []string      `json:"framework_security"`
	SecurityHeaders   []string      `json:"security_headers"`
	DeploymentSignals []string      `json:"deployment_signals"`
}

// ReconResult is the comprehensive RECON context (DESIGN.md §4.3).
//
// Ports schemas/recon.py ReconResult. Seeded (defaults.go): languages and
// frameworks default to `[]`; the five nested models are REQUIRED in Python,
// so NewReconResult seeds them with their own defaults rather than leaving
// half-built zero values.
type ReconResult struct {
	Architecture         ArchitectureMap  `json:"architecture"`
	DataFlows            DataFlowMap      `json:"data_flows"`
	Dependencies         DependencyReport `json:"dependencies"`
	Config               ConfigReport     `json:"config"`
	SecurityContext      SecurityContext  `json:"security_context"`
	Languages            []string         `json:"languages"`
	Frameworks           []string         `json:"frameworks"`
	LinesOfCode          int              `json:"lines_of_code"`
	FileCount            int              `json:"file_count"`
	ReconDurationSeconds float64          `json:"recon_duration_seconds"`
}

// ---------------------------------------------------------------------------
// Flat harness schemas for RECON agents
// ---------------------------------------------------------------------------
// These are what the LLM actually produces via .harness() calls: only flat
// fields (string, []string), no nesting. agents/recon/_parsers.py converts
// them into the structured schemas above.
// ---------------------------------------------------------------------------

// ArchitectureMapRaw is the flat harness output for the architecture mapper.
//
// Ports schemas/recon.py ArchitectureMapRaw. Seeded (defaults.go):
// app_type="unknown", all five list fields `[]`.
type ArchitectureMapRaw struct {
	// AppType is one of: web_api, cli_tool, library, microservice, monolith.
	AppType string `json:"app_type"`
	// Modules: one string per module, "name | path | language | description".
	Modules []string `json:"modules"`
	// EntryPoints: "kind | route_or_id | file_path:line | auth_required".
	EntryPoints []string `json:"entry_points"`
	// TrustBoundaries: "name | source_zone | target_zone | description".
	TrustBoundaries []string `json:"trust_boundaries"`
	// Services: "name | type | endpoint | auth_mechanism".
	Services []string `json:"services"`
	// APIEndpoints: "method | path | handler | file_path:line | auth_required | rate_limited".
	APIEndpoints []string `json:"api_endpoints"`
}

// DataFlowMapRaw is the flat harness output for the data flow mapper.
//
// Ports schemas/recon.py DataFlowMapRaw. Seeded (defaults.go): all three list
// fields `[]`.
type DataFlowMapRaw struct {
	// Flows: "source | sink | sanitized(true/false) | file1, file2, ...".
	Flows []string `json:"flows"`
	// SanitizationPoints: "file_path:line | function_name | type | protects_against".
	SanitizationPoints []string `json:"sanitization_points"`
	// Sinks: "sink_type | file_path:line | function_name | notes".
	Sinks []string `json:"sinks"`
}

// DependencyReportRaw is the flat harness output for the dependency auditor.
//
// Ports schemas/recon.py DependencyReportRaw. Seeded (defaults.go): all three
// list fields `[]`.
type DependencyReportRaw struct {
	// Sbom: "name | version | ecosystem | direct(true/false) | license".
	Sbom []string `json:"sbom"`
	// KnownCves: "cve_id | package | installed_version | fixed_version | cvss_score | direct | reachable".
	KnownCves []string `json:"known_cves"`
	// Outdated: "package | current_version | latest_version | direct(true/false)".
	Outdated []string `json:"outdated"`
}

// ConfigReportRaw is the flat harness output for the config scanner.
//
// Ports schemas/recon.py ConfigReportRaw. Seeded (defaults.go): both list
// fields `[]`.
type ConfigReportRaw struct {
	// Secrets: "type | file_path:line | match_preview | confidence | is_test(true/false)".
	Secrets []string `json:"secrets"`
	// Misconfigs: "category | file_path:line | key | risk | remediation".
	Misconfigs []string `json:"misconfigs"`
}

// SecurityContextRaw is the flat harness output for the security context
// profiler.
//
// Ports schemas/recon.py SecurityContextRaw. Seeded (defaults.go):
// auth_details="" (the Go zero value, so only the list fields actually need
// seeding), crypto_usage and security_signals `[]`.
type SecurityContextRaw struct {
	// AuthModel is one of: jwt, session_cookie, oauth2, api_key, none, other.
	AuthModel string `json:"auth_model"`
	// AuthDetails is a brief description of the auth implementation.
	AuthDetails string `json:"auth_details"`
	// CryptoUsage: "algorithm | key_size | mode | usage_context | is_weak(true/false)".
	CryptoUsage []string `json:"crypto_usage"`
	// SecuritySignals: framework security features, security headers and
	// deployment signals, one per entry.
	SecuritySignals []string `json:"security_signals"`
}
