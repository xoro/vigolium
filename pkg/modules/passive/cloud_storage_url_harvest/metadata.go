package cloud_storage_url_harvest

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-url-harvest"
	ModuleName  = "Cloud Storage URL Harvester"
	ModuleShort = "Harvests object-storage/CDN object URLs from page bodies and queues them for traversal probing"
)

var (
	ModuleDesc = `## Description
Passively mines in-scope HTML/JS/JSON response bodies for object-storage object
URLs — vanity-CDN ` + "`/obj/<bucket>/<object>`" + ` shapes plus AWS S3, GCS and Azure
endpoints — and injects a GET for each newly-seen bucket back into the scan
pipeline. This lets the active CDN object-storage traversal module probe storage
objects that are only *referenced* in pages (and would otherwise be filtered as
static assets) without storing their (often binary) bodies.

## Notes
- Skips static/asset response bodies (only mines text: html/js/json)
- Deduplicates per (host, bucket-prefix) — the traversal bug is per-bucket
- Fed requests re-enter the pipeline and are scanned like any other request

## References
- https://hackerone.com/reports/3523931`

	ModuleConfirmation = "Informational: lists object-storage object URLs discovered in response bodies and queued for active probing."
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "cloud-storage", "discovery", "passive", "light"}
)
