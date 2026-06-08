package config

import "github.com/vigolium/vigolium/pkg/httpmsg"

// HTTPConfig holds global outbound-HTTP settings applied across every scan
// phase (dynamic-assessment, discovery, fingerprinting, external harvesting).
// Nested under scanning_strategy; config path is scanning_strategy.http.*.
type HTTPConfig struct {
	// UserAgent selects the User-Agent header sent on every outgoing scanner
	// request (modules that deliberately inject their own User-Agent keep
	// theirs). Accepted values:
	//   "preset" — the self-identifying Vigolium string (the default):
	//     "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)".
	//     {version} is replaced with the running binary version.
	//   "random" — rotate a realistic browser string per request.
	//   ""       — blank behaves exactly like "random".
	//   <any>    — use the literal string verbatim ({version} still expands).
	// The VIGOLIUM_DEFAULT_UA env var overrides this when set, and an explicit
	// -H 'User-Agent: ...' flag still takes precedence for dynamic-assessment.
	UserAgent string `yaml:"user_agent"`
}

// DefaultHTTPConfig returns the default HTTP config: the "preset" selector, so
// requests carry the honest, self-identifying Vigolium User-Agent unless the
// operator opts into "random" or a literal override.
func DefaultHTTPConfig() *HTTPConfig {
	return &HTTPConfig{
		UserAgent: httpmsg.UserAgentPreset,
	}
}
