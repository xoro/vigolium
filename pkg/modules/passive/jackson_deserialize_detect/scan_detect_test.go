package jackson_deserialize_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api/obj HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_TypeField drives a JSON response carrying a Jackson type
// discriminator (@class) and expects a deserialization-indicator finding.
func TestScanPerRequest_TypeField(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"@class":"com.example.User","name":"alice"}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Jackson/Java Deserialization Indicators", results[0].Info.Name)
}

// TestScanPerRequest_JacksonError drives a body with a Jackson mapping exception
// (any content type) and expects a finding.
func TestScanPerRequest_JacksonError(t *testing.T) {
	t.Parallel()
	m := New()
	body := `com.fasterxml.jackson.databind.JsonMappingException: cannot deserialize`
	ctx := makeHTTPCtx("text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_DeserError drives a Java ObjectInputStream deserialization
// error and expects a finding.
func TestScanPerRequest_DeserError(t *testing.T) {
	t.Parallel()
	m := New()
	body := `java.io.InvalidClassException: local class incompatible`
	ctx := makeHTTPCtx("text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_JSAssetReverseDNS is a regression for the FP class where a
// minified JS bundle (served text/javascript) full of reverse-DNS identifiers
// like "io.foo"/"com.app.title" tripped the Java-class-ref needle into a Medium.
func TestScanPerRequest_JSAssetReverseDNS(t *testing.T) {
	t.Parallel()
	m := New()
	body := `var a={"com.app.title":"x","io.module.name":"y"};function NN(){return a}`
	ctx := makeHTTPCtx("text/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_BareClassRefNoDiscriminator ensures a JSON body with a
// Java-package-shaped string but NO @class/@type discriminator does not fire —
// a bare class reference is not evidence of polymorphic deserialization.
func TestScanPerRequest_BareClassRefNoDiscriminator(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"plugin":"com.example.SomeThing","enabled":true}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign drives a plain JSON response with no Jackson/Java
// indicators and expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"name":"alice","age":30}`
	ctx := makeHTTPCtx("application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
