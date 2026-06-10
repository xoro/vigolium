package oast

import (
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestExtractNonce(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"abc123nonce456.oast.pro", "abc123nonce456"},
		{"correlationid.server.example.com", "correlationid"},
		{"nodot", ""},
		{"", ""},
		{".leading-dot", ""},
	}

	for _, tt := range tests {
		got := extractNonce(tt.url)
		if got != tt.want {
			t.Errorf("extractNonce(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestNewDisabledConfig(t *testing.T) {
	cfg := &config.OASTConfig{Enabled: false}
	svc, err := New(cfg, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected nil service when disabled")
	}
}

func TestNewNilConfig(t *testing.T) {
	svc, err := New(nil, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Fatal("expected nil service for nil config")
	}
}

func TestEnabledNilService(t *testing.T) {
	var svc *Service
	if svc.Enabled() {
		t.Fatal("nil service should not be enabled")
	}
}

func TestGenerateURLNilService(t *testing.T) {
	var svc *Service
	url := svc.GenerateURL("http://target.com", "url", "param", "mod-id", "hash123")
	if url != "" {
		t.Fatalf("expected empty URL from nil service, got %q", url)
	}
}

func TestFlushCloseNilService(t *testing.T) {
	// Should not panic on nil receiver
	var svc *Service
	svc.Flush()
	svc.Close()
	svc.Start()
}

func TestSetRequestUUIDResolverNilService(t *testing.T) {
	// Should not panic on nil receiver
	var svc *Service
	svc.SetRequestUUIDResolver(func(hash string) string { return "uuid-123" })
}

func TestSaveFindingNoRepo(t *testing.T) {
	// saveFinding with nil repo should not panic
	svc := &Service{}
	svc.saveFinding(nil, "hash123")
}

func TestSaveFindingEmptyHash(t *testing.T) {
	// saveFinding with empty request hash should be a no-op
	svc := &Service{repo: nil}
	svc.saveFinding(nil, "")
}

func extractedValue(results []string, prefix string) (string, bool) {
	for _, r := range results {
		if strings.HasPrefix(r, prefix) {
			return strings.TrimPrefix(r, prefix), true
		}
	}
	return "", false
}

// TestEnrichOASTResult verifies an out-of-band finding is made self-tracing: the
// planting request/response are embedded and human-readable anchors (origin
// request, http_record UUID, planted callback URL, callback evidence) are added.
func TestEnrichOASTResult(t *testing.T) {
	interaction := &server.Interaction{
		Protocol:      "http",
		UniqueID:      "nonce123",
		RawRequest:    "GET / HTTP/1.1\r\nHost: nonce123.oast.pro\r\n\r\n",
		RawResponse:   "HTTP/1.1 200 OK\r\n\r\n",
		RemoteAddress: "203.0.113.7",
		Timestamp:     time.Date(2026, 6, 9, 5, 30, 37, 0, time.UTC),
	}
	pctx := PayloadContext{
		TargetURL:     "http://victim.example/css",
		ParameterName: "request-line",
		InjectionType: "routing-ssrf (request-line)",
		ModuleID:      "routing-ssrf",
		RequestHash:   "deadbeef",
		CallbackURL:   "http://nonce123.oast.pro",
	}
	origin := &database.HTTPRecord{
		UUID:        "d85c371d-e536-4ad5-b00c-8204f32ddcfe",
		Method:      "GET",
		URL:         "http://victim.example/css",
		RawRequest:  []byte("GET /css HTTP/1.1\r\nHost: victim.example\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody"),
	}

	sev, desc := classifyInteraction(interaction.Protocol, pctx)
	result := &output.ResultEvent{
		ModuleID: pctx.ModuleID,
		Info:     output.Info{Description: desc, Severity: sev},
		ExtractedResults: []string{
			"protocol=" + interaction.Protocol,
			"oast_id=" + interaction.UniqueID,
			"remote_addr=" + interaction.RemoteAddress,
		},
	}

	enrichOASTResult(result, interaction, pctx, origin)

	// The planting request/response are embedded inline.
	if result.Request != string(origin.RawRequest) {
		t.Errorf("Request not embedded: got %q", result.Request)
	}
	if result.Response != string(origin.RawResponse) {
		t.Errorf("Response not embedded: got %q", result.Response)
	}

	// Trace anchors are present in extracted-results.
	if v, ok := extractedValue(result.ExtractedResults, "http_record="); !ok || v != origin.UUID {
		t.Errorf("http_record anchor missing/wrong: %q ok=%v", v, ok)
	}
	if v, ok := extractedValue(result.ExtractedResults, "callback_url="); !ok || v != pctx.CallbackURL {
		t.Errorf("callback_url anchor missing/wrong: %q ok=%v", v, ok)
	}
	if v, ok := extractedValue(result.ExtractedResults, "origin_request="); !ok || v != "GET http://victim.example/css" {
		t.Errorf("origin_request anchor missing/wrong: %q ok=%v", v, ok)
	}
	if _, ok := extractedValue(result.ExtractedResults, "interacted_at="); !ok {
		t.Error("interacted_at anchor missing")
	}

	// Description is self-describing in plain-text outputs.
	if !strings.Contains(result.Info.Description, origin.UUID) ||
		!strings.Contains(result.Info.Description, "GET http://victim.example/css") {
		t.Errorf("description missing origin anchors: %q", result.Info.Description)
	}

	// The out-of-band callback request is retained as evidence.
	if len(result.AdditionalEvidence) == 0 ||
		!strings.Contains(result.AdditionalEvidence[0], "nonce123.oast.pro") {
		t.Errorf("callback evidence missing: %v", result.AdditionalEvidence)
	}
}

// TestEnrichOASTResultNoOrigin verifies enrichment degrades gracefully when the
// originating record could not be recovered (e.g. a fixed-URL OAST callback).
func TestEnrichOASTResultNoOrigin(t *testing.T) {
	interaction := &server.Interaction{Protocol: "dns", UniqueID: "n", RemoteAddress: "198.51.100.4"}
	pctx := PayloadContext{InjectionType: "parameter", CallbackURL: "http://n.oast.pro"}
	result := &output.ResultEvent{Info: output.Info{Description: "base"}}

	enrichOASTResult(result, interaction, pctx, nil)

	if result.Request != "" || result.Response != "" {
		t.Error("expected no embedded request/response without an origin record")
	}
	if _, ok := extractedValue(result.ExtractedResults, "http_record="); ok {
		t.Error("did not expect an http_record anchor without an origin record")
	}
	if v, ok := extractedValue(result.ExtractedResults, "callback_url="); !ok || v != pctx.CallbackURL {
		t.Errorf("callback_url anchor should still be present: %q ok=%v", v, ok)
	}
}

func TestClassifyInteraction(t *testing.T) {
	pctx := PayloadContext{
		TargetURL:     "http://target.com",
		ParameterName: "url",
		InjectionType: "parameter",
	}

	tests := []struct {
		protocol    string
		wantHighSev bool // true = High, false = not High
	}{
		{"http", true},
		{"https", true},
		{"HTTP", true},
		{"dns", false},
		{"smtp", false},
	}

	for _, tt := range tests {
		sev, desc := classifyInteraction(tt.protocol, pctx)
		if tt.wantHighSev && sev.String() != "high" {
			t.Errorf("classifyInteraction(%q) severity = %s, want high; desc: %s", tt.protocol, sev, desc)
		}
		if !tt.wantHighSev && sev.String() == "high" {
			t.Errorf("classifyInteraction(%q) severity = high, expected non-high; desc: %s", tt.protocol, desc)
		}
		if desc == "" {
			t.Errorf("classifyInteraction(%q) returned empty description", tt.protocol)
		}
	}
}
