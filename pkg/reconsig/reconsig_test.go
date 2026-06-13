package reconsig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractHosts(t *testing.T) {
	t.Parallel()
	body := `origin:"https://cds-apps-harvester-dev.hi5.platform.navify.com",` +
		`url:"https://su-appsdev.appsdev-tumorboard.hi5.platform.navify.com",` +
		`authDomain:"harvester-dev-env.firebaseapp.com",` +
		`version:e(26660).version,exports.default,a.b`
	hosts := ExtractHosts(body, 100)

	assert.Contains(t, hosts, "cds-apps-harvester-dev.hi5.platform.navify.com")
	assert.Contains(t, hosts, "su-appsdev.appsdev-tumorboard.hi5.platform.navify.com")
	assert.Contains(t, hosts, "harvester-dev-env.firebaseapp.com")
	// Numeric "version" tokens and single-letter TLDs are not FQDN-shaped.
	assert.NotContains(t, hosts, "26660.version")
	assert.NotContains(t, hosts, "a.b")
}

func TestExtractHostsDedup(t *testing.T) {
	t.Parallel()
	hosts := ExtractHosts("a.example.com a.example.com a.example.com", 100)
	assert.Equal(t, []string{"a.example.com"}, hosts)
}

func TestNormalizeHost(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "a.example.com", NormalizeHost("A.Example.com:443"))
	assert.Equal(t, "a.example.com", NormalizeHost(" a.example.com. "))
	assert.Equal(t, "", NormalizeHost(""))
}

func TestRegistrableDomain(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"cds-apps-harvester-dev.hi5.platform.navify.com": "navify.com",
		"https://app.navify.com/path":                    "navify.com",
		"sub.example.co.uk":                              "example.co.uk",
		"foo.myapp.vercel.app":                           "myapp.vercel.app", // PSL private suffix
		"exports.default":                                "exports.default",  // unmanaged TLD, still resolves
		"localhost":                                      "",
		"":                                               "",
	}
	for in, want := range cases {
		assert.Equal(t, want, RegistrableDomain(in), "RegistrableDomain(%q)", in)
	}
}

func TestIsScannableContentType(t *testing.T) {
	t.Parallel()
	for _, ct := range []string{"text/html; charset=utf-8", "application/javascript", "application/json", "text/plain"} {
		assert.True(t, IsScannableContentType(ct), ct)
	}
	for _, ct := range []string{"image/png", "font/woff2", "application/octet-stream", "video/mp4"} {
		assert.False(t, IsScannableContentType(ct), ct)
	}
}
