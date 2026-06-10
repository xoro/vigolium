package internal_header_probe

import "github.com/google/uuid"

// probeValue is one value the battery sets a candidate header to, plus a short
// label used in finding evidence.
type probeValue struct {
	label string
	value string
}

// battery returns the per-probe value set. A fresh UUID is generated each call so
// it cannot collide with anything already on the page. The classes mirror the
// user-selected battery: identity (uuid), role/trust words, booleans, routing /
// loopback IPs, and empty/null. The OAST callback is handled separately (planted
// for every candidate, independent of the body-diff arm).
func battery() []probeValue {
	return []probeValue{
		{"uuid", uuid.NewString()},
		{"admin", "admin"},
		{"internal", "internal"},
		{"root", "root"},
		{"true", "true"},
		{"one", "1"},
		{"loopback-ip", "127.0.0.1"},
		{"localhost", "localhost"},
		{"empty", ""},
		{"null", "null"},
	}
}
