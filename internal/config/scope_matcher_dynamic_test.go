package config

import "testing"

// restrictiveMatcher returns a matcher whose Host rule admits only allowHost.
func restrictiveMatcher(allowHost string) *ScopeMatcher {
	cfg := *DefaultScopeConfig()
	cfg.Host = ScopeRule{Include: []string{allowHost}}
	return NewScopeMatcher(cfg)
}

func TestAllowHost_AdmitsExactHost(t *testing.T) {
	m := restrictiveMatcher("app.navify.com")

	if m.InScopeRequest("api.navify.com", "/", "", "") {
		t.Fatal("api.navify.com should be out of scope before AllowHost")
	}
	m.AllowHost("api.navify.com")
	if !m.InScopeRequest("api.navify.com", "/", "", "") {
		t.Fatal("api.navify.com should be in scope after AllowHost")
	}
	// The apex is NOT wildcarded: a sibling that was never allowed stays out.
	if m.InScopeRequest("other.navify.com", "/", "", "") {
		t.Fatal("other.navify.com must remain out of scope (no apex wildcard)")
	}
}

// TestAllowHost_OverridesCachedNegative guards the ordering bug where a host
// checked (and cached false) before AllowHost would stay rejected.
func TestAllowHost_OverridesCachedNegative(t *testing.T) {
	m := restrictiveMatcher("app.navify.com")

	if m.InScopeRequest("late.navify.com", "/", "", "") {
		t.Fatal("precondition: late.navify.com out of scope")
	}
	m.AllowHost("late.navify.com")
	if !m.InScopeRequest("late.navify.com", "/", "", "") {
		t.Fatal("AllowHost must override the cached negative result")
	}
}

func TestAllowHost_CaseInsensitiveAndEmptySafe(t *testing.T) {
	m := restrictiveMatcher("app.navify.com")
	m.AllowHost("")          // no-op, must not panic
	m.AllowHost("API.Navify.COM")
	if !m.InScopeRequest("api.navify.com", "/", "", "") {
		t.Fatal("AllowHost should match host case-insensitively")
	}
}
