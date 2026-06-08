package nosqli_error_based

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// mongoErrorEcho simulates a server that leaks a MongoDB driver error when the
// named parameter carries injection metacharacters — the telltale of an
// error-based NoSQL injection.
func mongoErrorEcho(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if strings.ContainsAny(v, `'"${`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("MongoError: unknown top level operator: $gt near the query parser"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}
}

// TestScanPerInsertionPoint_DetectsNoSQLError drives the real scan method
// against a server that leaks a MongoDB error on injection.
func TestScanPerInsertionPoint_DetectsNoSQLError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(mongoErrorEcho("q"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a NoSQLi finding when a MongoDB error is leaked")
	assert.Equal(t, "q", res[0].FuzzingParameter)
	assert.Contains(t, res[0].Info.Description, "MongoDB")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never emits a
// DB error yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>results</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never leaks a DB error must not yield a NoSQLi finding")
}

// TestScanPerInsertionPoint_SkipsWAFChallenge reproduces a real false positive:
// a Cloudflare 403 "Just a moment..." challenge whose base64 token contained the
// substring "bSON", matching the MongoDB error pattern. A WAF/challenge response
// must never be mistaken for an application-emitted DB error.
func TestScanPerInsertionPoint_SkipsWAFChallenge(t *testing.T) {
	t.Parallel()
	// The literal token from the observed Cloudflare challenge body that the
	// (?i)BSON pattern matched: "...WqVZzyifbSONOgi1jV6J...".
	const cfBody = `<!DOCTYPE html><html><head><title>Just a moment...</title></head>` +
		`<body><script>window._cf_chl_opt={md:'iMQ_6kBnAtoBSYBDz0zw...WqVZzyifbSONOgi1jV6JfU_Yj6osB8oy64IDs'};</script></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(cfBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Cloudflare WAF challenge must not be reported as NoSQLi")
}

// TestCheckNoSQLError exercises the pure error-matching helper, including the
// baseline-suppression branch.
func TestCheckNoSQLError(t *testing.T) {
	t.Parallel()

	dbms, re, ok := checkNoSQLError("E11000 duplicate key error collection", "")
	require.True(t, ok)
	assert.Equal(t, "MongoDB", dbms)
	require.NotNil(t, re)

	_, _, ok = checkNoSQLError("nothing interesting here", "")
	assert.False(t, ok, "benign body must not match")

	// Error already present in the baseline is suppressed.
	_, _, ok = checkNoSQLError("E11000 duplicate key", "E11000 duplicate key")
	assert.False(t, ok, "error present in baseline must be suppressed")

	// The bare 4-char "BSON" / 6-char "mongod" tokens and the generic English
	// phrases that previously matched random base64 / SPA noise must no longer
	// fire on their own — only genuine driver/error-context forms do.
	for _, noise := range []string{
		"WqVZzyifbSONOgi1jV6JfU_Yj6osB8oy64IDs", // base64 token containing "bSON"
		"a1dKZ0ZrdlpkNVJfOUVtTU8zUDUyZ2tVMjdn",  // Salesforce fwuid-style token
		"this was a bad query for the user",     // generic English
		"that is an invalid operator here",      // generic English
		"see the mongoduck mascot",              // "mongod" inside a word
	} {
		_, _, ok = checkNoSQLError(noise, "")
		assert.Falsef(t, ok, "weak-token noise %q must not be matched", noise)
	}

	// Genuine driver/error-context forms still match.
	for _, hit := range []string{
		"MongoServerError: unknown operator: $gt",
		"caught BSONError: invalid BSON",
		"com.mongodb.MongoException: bad cmd",
		"Cannot apply $inc update operator to non-numeric",
	} {
		_, _, ok = checkNoSQLError(hit, "")
		assert.Truef(t, ok, "genuine Mongo error %q must still match", hit)
	}
}

// TestScanPerInsertionPoint_Skips404SPAShell reproduces the motivating false
// positive: a Salesforce community 404 SPA shell that returns a fresh batch of
// random base64 tokens on every request — one of which matched the old short
// "BSON" pattern in the fuzzed response but not the captured baseline. A 404 is
// not an application error surface, so it must never be reported as NoSQLi.
func TestScanPerInsertionPoint_Skips404SPAShell(t *testing.T) {
	t.Parallel()
	tokens := []string{
		"WqVZzyifbSONOgi1jV6JfU_Yj6osB8oy64IDs",
		"kWJgFkvZd5R9EmMO3P52gkU27gLaDEE6KqIWkq",
		"iMQ6kBnAtoBSYBDz0zwTU8zUDUyZ2tVMjdnTGFE",
	}
	var i int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A different random-ish token on every request, like the real shell.
		tok := tokens[i%len(tokens)]
		i++
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Help Center</title></head><body>` +
			`<script>var fwuid="` + tok + `";</script></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 404 SPA shell with random tokens must not be reported as NoSQLi")
}

// TestScanPerInsertionPoint_RejectsNonReproducingToken ensures a one-off random
// token that matches a (tightened) pattern in a single 200 response — but does
// not recur on re-send — is dropped by the reproduce/control confirmation.
func TestScanPerInsertionPoint_RejectsNonReproducingToken(t *testing.T) {
	t.Parallel()
	var i int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i++
		// Only the very first injected request leaks a genuine-looking marker;
		// every subsequent request (the reproduce re-send and the control) is
		// clean — so the confirmation must reject it.
		if i == 1 {
			_, _ = w.Write([]byte("transient BSONError glitch"))
			return
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-reproducing one-off token match must be dropped")
}
