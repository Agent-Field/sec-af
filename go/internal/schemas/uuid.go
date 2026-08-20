package schemas

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewUUID4 returns a random RFC 4122 version-4 UUID in the canonical
// 8-4-4-4-12 lowercase hex form, e.g. "1b4e28ba-2fa1-4d1d-883f-9e0d5a1e0f2b".
//
// Ports Python's `default_factory=lambda: str(uuid4())` (schemas/hunt.py,
// schemas/recon.py, schemas/prove.py). The port takes no new third-party
// dependency (docs/DESIGN.md §0.6), so this builds the value from crypto/rand
// directly: 16 random bytes with the version nibble forced to 4 and the variant
// bits forced to 10xx, exactly as CPython's `uuid.uuid4()` does.
//
// It panics only if the system CSPRNG fails, which crypto/rand documents as
// unrecoverable — the same posture as `uuid.uuid4()`, which has no failure mode
// a caller could act on.
func NewUUID4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("schemas.NewUUID4: crypto/rand failed: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx (RFC 4122)

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
