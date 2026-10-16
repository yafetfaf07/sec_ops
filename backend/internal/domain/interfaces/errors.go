// Package interfaces declares the domain ports (repositories and external
// services) and the shared sentinel errors.
//
// ALL sentinel errors live here. Infrastructure translates driver/HTTP errors
// into these, use cases return them (optionally wrapped with %w), and handlers
// map them to status codes with errors.Is. This keeps infrastructure from
// importing use-case packages, which personal_prod_golang's task repo did.
package interfaces

import "errors"

var (
	// ErrNotFound -> 404
	ErrNotFound = errors.New("not found")
	// ErrForbidden -> 403 (authenticated but not permitted)
	ErrForbidden = errors.New("forbidden")
	// ErrUnauthorized -> 401
	ErrUnauthorized = errors.New("unauthorized")
	// ErrValidation -> 400. Wrap with details: fmt.Errorf("%w: field x", ErrValidation)
	ErrValidation = errors.New("validation failed")
	// ErrConflict -> 409 (duplicate, concurrent scan, etc.)
	ErrConflict = errors.New("conflict")
	// ErrInvalidTransition -> 409 (incident state machine)
	ErrInvalidTransition = errors.New("invalid status transition")
	// ErrImmutable -> 409. Raised by DB triggers on append-only tables.
	ErrImmutable = errors.New("record is immutable")
	// ErrQuotaExceeded -> 429 (Gemini / AbuseIPDB daily budget or upstream 429)
	ErrQuotaExceeded = errors.New("upstream quota exceeded")
	// ErrUpstreamUnavailable -> 503
	ErrUpstreamUnavailable = errors.New("upstream service unavailable")
)
