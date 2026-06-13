package httpmsg

import (
	"bytes"
	"testing"
)

func TestHttpResponse_Head(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "head and body split at blank line",
			raw:  "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>",
			want: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
		},
		{
			name: "no body still returns full head",
			raw:  "HTTP/1.1 204 No Content\r\nX-Test: 1\r\n\r\n",
			want: "HTTP/1.1 204 No Content\r\nX-Test: 1\r\n\r\n",
		},
		{
			name: "empty response yields nil head",
			raw:  "",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := NewHttpResponse([]byte(tc.raw))
			head := resp.Head()
			if string(head) != tc.want {
				t.Errorf("Head() = %q, want %q", head, tc.want)
			}
			// Head and Body must reconstruct the original raw bytes exactly.
			if len(tc.raw) > 0 && resp.BodyOffset() > 0 {
				combined := append(append([]byte{}, resp.Head()...), resp.Body()...)
				if !bytes.Equal(combined, []byte(tc.raw)) {
					t.Errorf("Head()+Body() = %q, want %q", combined, tc.raw)
				}
			}
		})
	}
}
