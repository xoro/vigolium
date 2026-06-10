package cdn_object_traversal_listing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cdn-object-traversal-listing"
	ModuleName  = "CDN Object-Storage Traversal Listing"
	ModuleShort = "Detects bucket object enumeration via ..; path traversal on CDN-fronted object storage"
)

var (
	ModuleDesc = `## Description
Detects directory-traversal-driven bucket object enumeration on CDN-fronted
object storage (GCS, S3-compatible, TOS/OSS). A request path ending in a
non-canonical parent reference — most notably the matrix-parameter form ` + "`..;`" + `
and its encoded variants — is passed through the CDN/gateway unchanged but
collapsed to the parent directory by the storage backend, which then falls back
from GetObject to ListObjects and returns a bucket listing.

The semicolon is an RFC 3986 matrix-parameter delimiter: backends that strip it
turn ` + "`/<bucket>/<object>/..;`" + ` into ` + "`/<bucket>/<object>/..`" + `, resolving to the
bucket and triggering a listing. ` + "`path.Clean`" + `-based guards that only reject
` + "`..`/`../`" + ` miss the ` + "`..;`" + ` form.

## Payloads (appended as a trailing segment to the real object path)
- ` + "`..;`" + `, ` + "`%2e%2e%3b`" + `, double-encoded ` + "`%252e%252e%253b`" + `, ` + "`..;/`" + ` (documented)
- encoding / mangle / null / stacked variants (` + "`..%3b`, `%2e%2e;`, `..;a=b/`, `....;//`, `..;%00`, `..;/..;/`" + `)

## Confirmation
1. The object's own GET baseline contains no listing (and is re-checked for stability).
2. The probe returns a strong listing (ListBucketResult/EnumerationResults/storage#objects), absent from baseline.
3. A non-collapsing control suffix (e.g. ` + "`zz;`" + `) does NOT list — attributing the listing to the ..; collapse, not a catch-all.
4. The listing reproduces on a NoClustering re-fetch and is not the host wildcard.
Certain when the listing keys include the requested object's leaf (proving the parent directory was listed); Firm otherwise.

## References
- https://hackerone.com/reports/3523931
- https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d`

	ModuleConfirmation = "Confirmed when a ..;-family trailing payload turns an object fetch into a bucket listing absent from the stable baseline, a non-collapsing control does not list, and the listing reproduces."
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cloud", "cloud-storage", "path-traversal", "info-disclosure", "light"}
)
