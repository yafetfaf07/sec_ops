package security

import (
	"strings"
	"testing"
)

func TestBcryptHashAndCompare(t *testing.T) {
	h := NewBcryptHasher(4) // low cost for fast tests; production uses the default
	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("hash must not equal the plaintext")
	}
	if err := h.Compare(hash, "correct horse battery staple"); err != nil {
		t.Fatalf("Compare should succeed: %v", err)
	}
	if err := h.Compare(hash, "wrong password"); err == nil {
		t.Fatal("Compare should fail for a wrong password")
	}
}

func TestBcryptRejectsOverlongPassword(t *testing.T) {
	h := NewBcryptHasher(4)
	// bcrypt silently truncates beyond 72 bytes; Hash must refuse instead of
	// accepting a password whose un-truncated tail is meaningless at login.
	if _, err := h.Hash(strings.Repeat("a", 73)); err == nil {
		t.Fatal("expected an error for a 73-byte password")
	}
}

func TestBcryptCompareDummyDoesNotPanic(t *testing.T) {
	h := NewBcryptHasher(4)
	h.CompareDummy("whatever") // must not panic; used to equalise login timing
}
