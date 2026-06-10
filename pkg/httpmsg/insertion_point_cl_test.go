package httpmsg

import (
	"bytes"
	"testing"
)

// TestBuildRequest_ContentLengthFastPath verifies the in-place Content-Length
// patch used on the fuzzing hot path: a single allocation that splices the
// payload and rewrites Content-Length without re-parsing every header.
func TestBuildRequest_ContentLengthFastPath(t *testing.T) {
	// Content-Length is deliberately NOT the last header — Content-Type follows
	// it — to exercise in-place patching (the header keeps its position).
	request := []byte("POST /api HTTP/1.1\r\nContent-Length: 9\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkey=value")
	bodyOffset := 90 // body "key=value" begins here
	param := NewParsedParam(ParamBody, "key", "value", bodyOffset, bodyOffset+3, bodyOffset+4, bodyOffset+9)

	ip := NewParameterInsertionPoint(request, param)
	if !ip.cl.fast {
		t.Fatalf("expected fast Content-Length path to be eligible for a body parameter with one Content-Length header")
	}

	cases := []struct {
		name     string
		payload  string
		expected string // exact request bytes
	}{
		{
			name:     "shorter body shrinks Content-Length",
			payload:  "x",
			expected: "POST /api HTTP/1.1\r\nContent-Length: 5\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkey=x",
		},
		{
			name:     "same-width Content-Length",
			payload:  "12345",
			expected: "POST /api HTTP/1.1\r\nContent-Length: 9\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkey=12345",
		},
		{
			name:     "longer body grows Content-Length width",
			payload:  "verylongvalue",
			expected: "POST /api HTTP/1.1\r\nContent-Length: 17\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nkey=verylongvalue",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ip.BuildRequest([]byte(tc.payload))
			if string(result) != tc.expected {
				t.Errorf("BuildRequest() = %q, want %q", result, tc.expected)
			}
			assertContentLengthMatchesBody(t, result)
		})
	}
}

// TestBuildRequest_ContentLengthFastPathMatchesSlowPath ensures the fast path
// produces a request whose Content-Length equals the real body length, agreeing
// with UpdateContentLength, across a range of payload sizes.
func TestBuildRequest_ContentLengthFastPathMatchesSlowPath(t *testing.T) {
	request := []byte("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=12345")
	bodyOffset := findBodyOffsetStrict(request, 0)
	if bodyOffset == -1 {
		t.Fatal("could not locate body offset")
	}
	// value "12345" sits at the end of the request.
	valueStart := len(request) - 5
	param := NewParsedParam(ParamBody, "a", "12345", bodyOffset, bodyOffset+1, valueStart, len(request))

	ip := NewParameterInsertionPoint(request, param)
	if !ip.cl.fast {
		t.Fatal("expected fast Content-Length path to be eligible")
	}

	for _, payload := range []string{"", "z", "ab", "0123456789", "this-is-a-much-longer-replacement-value"} {
		result := ip.BuildRequest([]byte(payload))
		assertContentLengthMatchesBody(t, result)
	}
}

// TestBuildRequest_NoContentLengthUsesSlowPath confirms requests without a
// Content-Length header still get one added (slow path), unchanged behaviour.
func TestBuildRequest_NoContentLengthUsesSlowPath(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}")
	bodyOffset := 54
	param := NewParsedParam(ParamJSON, "name", "test", bodyOffset+2, bodyOffset+6, bodyOffset+9, bodyOffset+13).WithJSONType(JSONTypeString)

	ip := NewParameterInsertionPoint(request, param)
	if ip.cl.fast {
		t.Fatal("expected slow path when the request has no Content-Length header")
	}

	result := ip.BuildRequest([]byte("hello world"))
	expected := "POST /api HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"name\":\"hello world\"}"
	if string(result) != expected {
		t.Errorf("BuildRequest() = %q, want %q", result, expected)
	}
}

// TestComputeCLRewrite_DuplicateContentLengthFallsBack ensures a malformed
// request with two Content-Length headers takes the slow path so duplicates are
// collapsed exactly as before.
func TestComputeCLRewrite_DuplicateContentLengthFallsBack(t *testing.T) {
	request := []byte("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
	bodyOffset := findBodyOffsetStrict(request, 0)
	param := NewParsedParam(ParamBody, "0", "hello", bodyOffset, bodyOffset, bodyOffset, bodyOffset+5)
	ip := NewParameterInsertionPoint(request, param)
	if ip.cl.fast {
		t.Fatal("expected slow path when the request has duplicate Content-Length headers")
	}
}

// benchBodyIP builds a realistic POST body insertion point with several
// headers around the Content-Length, the shape that dominates body fuzzing.
func benchBodyIP() (*ParameterInsertionPoint, []byte) {
	request := []byte("POST /api/login HTTP/1.1\r\n" +
		"Host: target.example.com\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n" +
		"Accept: */*\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 27\r\n" +
		"Cookie: session=abcdef123456\r\n" +
		"\r\n" +
		"username=admin&password=test")
	bodyOffset := findBodyOffsetStrict(request, 0)
	// value "test" at the end (password=test)
	valueStart := len(request) - 4
	param := NewParsedParam(ParamBody, "password", "test", bodyOffset+15, bodyOffset+23, valueStart, len(request))
	return NewParameterInsertionPoint(request, param), []byte("' OR 1=1-- a longer injection payload")
}

// BenchmarkBuildRequest_FastPath measures the in-place Content-Length patch.
func BenchmarkBuildRequest_FastPath(b *testing.B) {
	ip, payload := benchBodyIP()
	if !ip.cl.fast {
		b.Fatal("fast path not eligible")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ip.BuildRequest(payload)
	}
}

// BenchmarkBuildRequest_SlowPath measures the previous splice + full re-parse.
func BenchmarkBuildRequest_SlowPath(b *testing.B) {
	ip, payload := benchBodyIP()
	encoded := ip.encodePayload(payload)
	start := ip.parameter.ValueStart()
	end := ip.parameter.ValueEnd()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := ip.splice(encoded, start, end)
		_, _ = UpdateContentLength(result)
	}
}

// assertContentLengthMatchesBody parses the built request and checks that the
// Content-Length header value equals the actual body byte length.
func assertContentLengthMatchesBody(t *testing.T, request []byte) {
	t.Helper()
	bodyOffset := findBodyOffsetStrict(request, 0)
	if bodyOffset == -1 {
		t.Fatalf("built request has no header/body separator: %q", request)
	}
	bodyLen := len(request) - bodyOffset
	clValue, err := GetHeaderValue(request, "Content-Length")
	if err != nil {
		t.Fatalf("GetHeaderValue: %v", err)
	}
	if clValue != intToString(bodyLen) {
		t.Errorf("Content-Length = %q, want %d (body=%q)", clValue, bodyLen, request[bodyOffset:])
	}
	// Exactly one Content-Length header in the result.
	if n := bytes.Count(bytes.ToLower(request), []byte("content-length:")); n != 1 {
		t.Errorf("expected exactly one Content-Length header, found %d in %q", n, request)
	}
}
