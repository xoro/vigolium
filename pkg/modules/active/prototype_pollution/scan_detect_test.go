package prototype_pollution

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// pollutionServer simulates a stateful server-side prototype-pollution sink: keys
// injected via __proto__ persist globally and surface in the serialization of a
// FIXED object on every subsequent response, while normal (non-__proto__) input
// properties are NOT echoed. This is what distinguishes a real sink from a server
// that merely echoes request input.
func pollutionServer() *httptest.Server {
	var mu sync.Mutex
	polluted := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var parsed map[string]json.RawMessage
		_ = json.Unmarshal(b, &parsed)
		mu.Lock()
		if pp, ok := parsed["__proto__"]; ok {
			var kv map[string]string
			if json.Unmarshal(pp, &kv) == nil {
				for k, v := range kv {
					polluted[k] = v
				}
			}
		}
		out := map[string]string{"result": "ok"}
		for k, v := range polluted {
			out[k] = v
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(out)
		_, _ = w.Write(resp)
	}))
}

const benignJSONBody = `{"name":"alice"}`

// jsonPost builds a POST request with an application/json body so the module's
// CanProcess gate (POST/PUT/PATCH + JSON content type) is satisfied. modtest's
// RequestMethod hardcodes a form content type, so the raw request is assembled
// here directly.
func jsonPost(t *testing.T, rawURL, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	port := 80
	if p := u.Port(); p != "" {
		_, _ = fmt.Sscanf(p, "%d", &port)
	} else if u.Scheme == "https" {
		port = 443
	}

	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)

	target := u.RequestURI()
	if target == "" {
		target = "/"
	}
	raw := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		target, u.Host, len(body), body,
	)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// TestScanPerRequest_DetectsPollutionReflection drives the scan against a real
// stateful pollution sink (pollutionServer): __proto__-injected keys surface in
// the response, while plain input properties do not — so the fresh-canary +
// echo-control confirmation passes and a finding is emitted.
func TestScanPerRequest_DetectsPollutionReflection(t *testing.T) {
	t.Parallel()
	srv := pollutionServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding for a genuine prototype-pollution sink")
}

// TestScanPerRequest_EchoServerNoFalsePositive ensures an endpoint that simply
// echoes the request body back is NOT reported: the echo control (a plain marker
// never injected via __proto__) reflects, proving it's input reflection rather
// than prototype pollution.
func TestScanPerRequest_EchoServerNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b) // pure echo
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a pure echo endpoint must not be reported as prototype pollution")
}

// TestScanPerRequest_DetectsStatusPollution simulates a server that honors a
// polluted status property by returning HTTP 510, while the benign baseline is
// 200.
func TestScanPerRequest_DetectsStatusPollution(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"status":510`) {
			w.WriteHeader(510)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when status-code pollution flips the response to 510")
}

// TestScanPerRequest_TransientStatusNoFalsePositive ensures a one-shot 510 (only
// the first status payload returns 510, then 200) is dropped by the
// reproducibility gate.
func TestScanPerRequest_TransientStatusNoFalsePositive(t *testing.T) {
	t.Parallel()
	var statusHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `"status":510`) {
			if atomic.AddInt64(&statusHits, 1) == 1 {
				w.WriteHeader(510) // one-shot
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a one-shot transient 510 must not be reported")
}

// TestScanPerRequest_NoFalsePositive ensures a server that ignores the injected
// payloads (static benign response) yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := jsonPost(t, srv.URL+"/api/user", benignJSONBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server unaffected by pollution payloads must not yield findings")
}

// TestCanProcess validates the POST/PUT/PATCH + JSON gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	jsonReq := modtest.Response(jsonPost(t, "http://example.com/api", benignJSONBody), "application/json", "{}")
	assert.True(t, m.CanProcess(jsonReq), "POST with JSON body should be processable")

	getReq := modtest.Response(modtest.Request(t, "http://example.com/api"), "application/json", "{}")
	assert.False(t, m.CanProcess(getReq), "GET request should not be processable")
}
