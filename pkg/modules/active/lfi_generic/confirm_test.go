package lfi_generic

import (
	"encoding/base64"
	"testing"
)

func TestConfirmPHPFilterBase64(t *testing.T) {
	t.Parallel()
	phpSrc := base64.StdEncoding.EncodeToString([]byte("<?php $x = 1; echo $x; ?>"))
	pngBlob := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

	// dataWrapperPayload is the literal data:// wrapper the module injects; it
	// base64-encodes `<?php echo "vigolium-test"; ?>`.
	const dataWrapperPayload = "data://text/plain;base64,PD9waHAgZWNobyAidmlnb2xpdW0tdGVzdCI7ID8+"
	const reflectedBlob = "PD9waHAgZWNobyAidmlnb2xpdW0tdGVzdCI7ID8+"

	tests := []struct {
		name     string
		data     string
		baseline string
		payload  string
		want     bool
	}{
		{
			name: "base64 of PHP source confirms",
			data: phpSrc,
			want: true,
		},
		{
			name: "PHP base64 embedded in larger body confirms",
			data: "some prefix " + phpSrc + " trailing",
			want: true,
		},
		{
			name: "base64 PNG data-URI does not confirm",
			data: `<img src="data:image/png;base64,` + pngBlob + `">`,
			want: false,
		},
		{
			name:     "blob already in baseline is rejected",
			data:     phpSrc,
			baseline: phpSrc,
			want:     false,
		},
		{
			name: "no base64 at all",
			data: "<html><body>plain page</body></html>",
			want: false,
		},
		{
			// The reported Salesforce-Aura false positive: the endpoint echoes
			// our request body, so the data:// payload's base64 lands in the
			// response and naively decodes back to PHP. The payload-reflection
			// guard must reject it.
			name:    "reflected data:// payload is rejected via payload guard",
			data:    `{"loaded":{"app":"` + reflectedBlob + `"}}`,
			payload: dataWrapperPayload,
			want:    false,
		},
		{
			// Even with no payload context, the decoded marker alone proves the
			// blob is our own injected sentinel, never a real file read.
			name: "reflected payload rejected via marker even without payload",
			data: `{"loaded":{"app":"` + reflectedBlob + `"}}`,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := confirmPHPFilterBase64(tc.data, tc.baseline, tc.payload); got != tc.want {
				t.Fatalf("confirmPHPFilterBase64() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfirmWinIni(t *testing.T) {
	t.Parallel()
	realWinIni := "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n"

	tests := []struct {
		name     string
		data     string
		baseline string
		want     bool
	}{
		{name: "real win.ini confirms", data: realWinIni, want: true},
		{
			// The exact weakness of the former bare-word rule: prose mentioning
			// "fonts" and "extensions" with no bracketed sections.
			name: "prose mentioning fonts and extensions does not confirm",
			data: "We support custom fonts and browser extensions on this page.",
			want: false,
		},
		{
			name: "single section header is not enough",
			data: "[fonts]\nArial=arial.ttf\n",
			want: false,
		},
		{
			name:     "sections already in baseline are rejected",
			data:     realWinIni,
			baseline: realWinIni,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := confirmWinIni(tc.data, tc.baseline, ""); got != tc.want {
				t.Fatalf("confirmWinIni() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfirmAppConfig(t *testing.T) {
	t.Parallel()
	realEnv := "APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:abcd1234\nDB_CONNECTION=mysql\nDB_PASSWORD=supersecret\n"
	realHtaccess := "RewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n<Files .env>\n  Require all denied\n</Files>\n"

	tests := []struct {
		name     string
		data     string
		baseline string
		want     bool
	}{
		{name: "real .env with two sensitive assignments confirms", data: realEnv, want: true},
		{name: "real .htaccess with two directives confirms", data: realHtaccess, want: true},
		{
			// Bare words without the KEY=VALUE shape — what the old rule keyed
			// on — must not confirm.
			name: "prose mentioning DB_PASSWORD and APP_KEY does not confirm",
			data: "Set your DB_PASSWORD and APP_KEY in the documentation.",
			want: false,
		},
		{
			name: "a single assignment is not enough",
			data: "DB_PASSWORD=secret\n",
			want: false,
		},
		{
			name:     "assignments already in baseline are rejected",
			data:     realEnv,
			baseline: realEnv,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := confirmAppConfig(tc.data, tc.baseline, ""); got != tc.want {
				t.Fatalf("confirmAppConfig() = %v, want %v", got, tc.want)
			}
		})
	}
}
