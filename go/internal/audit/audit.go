// Package audit ports src/sec_af/audit.py — the audit domain scaffold from
// DESIGN.md §3 (Signal Cascade Pipeline).
//
// The Python module is a single-field dataclass stub with NO callers anywhere
// in src/ or tests/ (`grep -rn "sec_af.audit\|from .audit"` finds nothing): it
// is a placeholder for the aggregate model described in the product design doc,
// never wired into app.py, the orchestrator or any reasoner.
//
// It is ported here purely for 1:1 module completeness — the port's rule is
// that every Python module has a Go counterpart, so a reviewer diffing
// src/sec_af against go/internal finds no unexplained gaps. Nothing imports
// this package, and nothing should until the Python module grows a caller;
// SecurityAuditResult (internal/schemas) is the real audit output type.
package audit

// SecurityAudit is the stub audit aggregate model from DESIGN.md §7.3.
//
// Ports audit.py's `@dataclass(slots=True) class SecurityAudit`. The Python
// default is `status: str = "not_implemented"`, which is NOT the Go zero value,
// so construct one with NewSecurityAudit rather than a bare literal.
type SecurityAudit struct {
	Status string `json:"status"`
}

// NewSecurityAudit returns the dataclass default: status "not_implemented".
func NewSecurityAudit() SecurityAudit {
	return SecurityAudit{Status: "not_implemented"}
}
