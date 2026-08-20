package schemas

import (
	"regexp"
	"testing"
)

// uuid4Re matches the canonical RFC 4122 v4 form CPython's `str(uuid4())`
// produces: 32 lowercase hex digits in 8-4-4-4-12 groups, version nibble 4,
// variant nibble 8|9|a|b.
var uuid4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUUID4Format(t *testing.T) {
	for i := 0; i < 200; i++ {
		got := NewUUID4()
		if len(got) != 36 {
			t.Fatalf("NewUUID4() = %q, want 36 chars", got)
		}
		if !uuid4Re.MatchString(got) {
			t.Fatalf("NewUUID4() = %q, not an RFC 4122 v4 uuid", got)
		}
	}
}

func TestNewUUID4IsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		v := NewUUID4()
		if _, dup := seen[v]; dup {
			t.Fatalf("NewUUID4() repeated %q after %d draws", v, i)
		}
		seen[v] = struct{}{}
	}
}

func TestConstructorsMintDistinctUUIDs(t *testing.T) {
	// Python parity: each default_factory=lambda: str(uuid4()) call is
	// independent, so RawFinding gets two DIFFERENT uuids.
	rf := NewRawFinding()
	if rf.ID == rf.Fingerprint {
		t.Errorf("NewRawFinding minted the same uuid twice: %q", rf.ID)
	}
	for name, got := range map[string]string{
		"RawFinding.ID":          rf.ID,
		"RawFinding.Fingerprint": rf.Fingerprint,
		"PotentialChain.ChainID": NewPotentialChain().ChainID,
		"SecretFinding.ID":       NewSecretFinding().ID,
		"MisconfigFinding.ID":    NewMisconfigFinding().ID,
		"VerifiedFinding.ID":     NewVerifiedFinding().ID,
	} {
		if !uuid4Re.MatchString(got) {
			t.Errorf("%s = %q, want a uuid4", name, got)
		}
	}
}
