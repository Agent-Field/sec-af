package audit

import (
	"encoding/json"
	"testing"
)

// src/sec_af/audit.py has no Python test file — it is an uncalled stub. This
// test exists only to pin the one observable thing the dataclass declares: its
// default.

// TestNewSecurityAuditDefault pins `status: str = "not_implemented"`.
func TestNewSecurityAuditDefault(t *testing.T) {
	if got := NewSecurityAudit().Status; got != "not_implemented" {
		t.Errorf("Status = %q, want %q", got, "not_implemented")
	}
}

// TestSecurityAuditJSONKey pins the field name a serialized stub would carry.
func TestSecurityAuditJSONKey(t *testing.T) {
	b, err := json.Marshal(NewSecurityAudit())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"status":"not_implemented"}`; string(b) != want {
		t.Errorf("marshaled as %s, want %s", b, want)
	}
}
