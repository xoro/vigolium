package authzutil

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func reqWith(t *testing.T, headerLines string) *httpmsg.HttpRequest {
	t.Helper()
	raw := fmt.Sprintf("GET /api/profile?user_id=42 HTTP/1.1\r\nHost: example.com\r\n%s\r\n", headerLines)
	return httpmsg.NewHttpRequest([]byte(raw))
}

func TestRequestCarriesCredential(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		headers string
		want    bool
	}{
		{"none", "", false},
		{"authorization", "Authorization: Bearer abc\r\n", true},
		{"cookie", "Cookie: session=xyz\r\n", true},
		{"api key header", "X-Api-Key: k-123\r\n", true},
		{"access token header", "X-Access-Token: t-123\r\n", true},
		{"benign header only", "Accept: text/html\r\nUpgrade-Insecure-Requests: 1\r\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RequestCarriesCredential(reqWith(t, tc.headers)); got != tc.want {
				t.Fatalf("RequestCarriesCredential(%q) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}

func TestRequestCarriesCredential_QueryToken(t *testing.T) {
	t.Parallel()
	raw := "GET /api/data?access_token=secret HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if !RequestCarriesCredential(httpmsg.NewHttpRequest([]byte(raw))) {
		t.Fatal("expected an access_token query parameter to count as a credential")
	}
	raw = "GET /api/data?page=4 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if RequestCarriesCredential(httpmsg.NewHttpRequest([]byte(raw))) {
		t.Fatal("a plain pagination parameter is not a credential")
	}
}

func TestRequestCarriesCredential_Nil(t *testing.T) {
	t.Parallel()
	if RequestCarriesCredential(nil) {
		t.Fatal("nil request must not be treated as credentialed")
	}
}

func TestBaselineLinksNeighbor(t *testing.T) {
	t.Parallel()
	body := `<html><a href="/blog/2/">Prev</a><a href="/blog/4/">Next</a></html>`
	cases := []struct {
		name   string
		body   string
		target string
		want   bool
	}{
		{"linked next", body, "/blog/4/", true},
		{"linked prev", body, "/blog/2/", true},
		{"unlinked sibling", body, "/blog/13/", false},
		{"query linked", `<a href="/list?page=4">Next</a>`, "/list?page=4", true},
		{"query unlinked", `<a href="/list?page=4">Next</a>`, "/list?page=9", false},
		{"bare numeric path is not specific", "see /4 and /5", "/4", false},
		{"empty body", "", "/blog/4/", false},
		{"empty target", body, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := BaselineLinksNeighbor(tc.body, tc.target); got != tc.want {
				t.Fatalf("BaselineLinksNeighbor(%q, %q) = %v, want %v", tc.body, tc.target, got, tc.want)
			}
		})
	}
}
