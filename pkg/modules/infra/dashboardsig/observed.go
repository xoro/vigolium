package dashboardsig

import "strings"

// Observed is the minimal view of an HTTP response the passive matcher needs.
// It is built once per response by the caller (passive/dashboard_fingerprint)
// and decouples the catalog from the httpmsg model.
type Observed struct {
	// Headers maps lowercased header name → value (last value wins, which is
	// fine for the unique single-valued headers the catalog keys on).
	Headers map[string]string
	// Cookies is the set of lowercased cookie names present in Set-Cookie.
	Cookies map[string]struct{}
	// Body is the response body (callers may cap its length before matching).
	Body string
}

// NewObserved builds an Observed from raw header pairs, Set-Cookie names and a
// body. headerName values are normalised to lowercase keys.
func NewObserved(headers map[string]string, cookieNames []string, body string) Observed {
	lh := make(map[string]string, len(headers))
	for k, v := range headers {
		lh[strings.ToLower(strings.TrimSpace(k))] = v
	}
	cs := make(map[string]struct{}, len(cookieNames))
	for _, c := range cookieNames {
		cs[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
	}
	return Observed{Headers: lh, Cookies: cs, Body: body}
}

func (o Observed) header(name string) (string, bool) {
	v, ok := o.Headers[strings.ToLower(strings.TrimSpace(name))]
	return v, ok
}

func (o Observed) hasCookie(name string) bool {
	_, ok := o.Cookies[strings.ToLower(strings.TrimSpace(name))]
	return ok
}
