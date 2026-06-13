package infra

import "strings"

// Shared internal / cloud-metadata SSRF target set used by the request-line
// routing modules (routing_ssrf, upgrade_routing_ssrf). Each target pairs an
// internal endpoint with self-evidencing response markers that prove the endpoint
// actually answered — distinctive tokens (ami-id, droplet_id, …) rather than the
// generic "this is an HTML page" markers used elsewhere, so a marker match here is
// strong evidence of a reached internal service rather than the app's own page.
//
// Kept deliberately separate from ssrf_detection's richer parameter-injection
// payload list (which carries broad page-shape markers and its own grading): those
// two contexts confirm differently, so they intentionally do not share a list.

// SSRFInternalTarget is an internal/metadata endpoint plus the markers and any
// endpoint-required headers needed to evidence reaching it.
type SSRFInternalTarget struct {
	// Effective is host[:port]/path WITHOUT a scheme and WITH a trailing path,
	// suitable to feed directly to RoutingTargets as the effective host.
	Effective string
	// Markers are self-evidencing tokens; any one present in the response body
	// (and absent from the baseline) evidences the endpoint answered.
	Markers []string
	// ExtraHeaders are headers the endpoint requires before it will answer (e.g.
	// GCP's Metadata-Flavor, Azure's Metadata). Empty for endpoints that answer
	// unconditionally (AWS IMDSv1, DigitalOcean).
	ExtraHeaders map[string]string
	// Label is a short human-readable name for findings.
	Label string
}

// InternalSSRFTargets returns the curated internal/metadata endpoints used to
// confirm a request-line routing SSRF in-band (no OAST callback is possible for an
// internal address). The list favours unauthenticated metadata services whose
// responses carry unmistakable tokens.
func InternalSSRFTargets() []SSRFInternalTarget {
	return []SSRFInternalTarget{
		{
			Effective: "169.254.169.254/latest/meta-data/",
			Markers:   []string{"ami-id", "instance-id", "local-hostname", "public-hostname", "iam/", "public-keys"},
			Label:     "AWS EC2 IMDSv1 metadata",
		},
		{
			Effective:    "metadata.google.internal/computeMetadata/v1/instance/",
			Markers:      []string{"hostname", "zone", "machine-type", "service-accounts/"},
			ExtraHeaders: map[string]string{"Metadata-Flavor": "Google"},
			Label:        "GCP compute metadata",
		},
		{
			Effective:    "169.254.169.254/metadata/instance?api-version=2021-02-01",
			Markers:      []string{"vmId", "vmSize", "azEnvironment", "resourceGroupName"},
			ExtraHeaders: map[string]string{"Metadata": "true"},
			Label:        "Azure IMDS metadata",
		},
		{
			Effective: "169.254.169.254/metadata/v1/",
			Markers:   []string{"droplet_id", "region", "interfaces/"},
			Label:     "DigitalOcean metadata",
		},
		{
			Effective: "100.100.100.200/latest/meta-data/",
			Markers:   []string{"instance-id", "image-id", "region-id", "zone-id"},
			Label:     "Alibaba Cloud metadata",
		},
	}
}

// MinMetadataMarkers is the number of DISTINCT self-evidencing tokens that must
// co-occur in a response before an in-band metadata hit is trusted. A single
// common word — "hostname", "region", "zone" — appears verbatim in ordinary HTML
// and JavaScript (e.g. `window.location.hostname`), so one match is not evidence;
// a genuine metadata directory listing or JSON document carries several together.
const MinMetadataMarkers = 2

// htmlPageSignatures are byte sequences that appear in an HTML document but never
// in a cloud metadata response (a plain-text directory listing or JSON).
var htmlPageSignatures = []string{"<!doctype html", "<html", "<head", "<body", "<script", "<meta ", "<div "}

// ConfirmFreshMetadata applies the in-band metadata gate that both routing SSRF
// modules share to a candidate response body: it rejects the application's own HTML
// page and requires at least MinMetadataMarkers distinct curated tokens present in
// body but absent from baseline. It returns the matched markers, and true only when
// both conditions hold (pass "" as baseline when there is none).
func ConfirmFreshMetadata(body, baseline string, markers []string) ([]string, bool) {
	if BodyLooksLikeHTMLPage(body) {
		return nil, false
	}
	fresh := FreshMetadataMarkers(body, baseline, markers)
	if len(fresh) < MinMetadataMarkers {
		return nil, false
	}
	return fresh, true
}

// MetadataBodyReproduces reports whether body is still a non-HTML metadata response
// carrying every marker in want — the per-round reproduction check shared by the
// routing SSRF confirmation loops. Lowercases body once.
func MetadataBodyReproduces(body string, want []string) bool {
	if len(want) == 0 {
		return false
	}
	lower := strings.ToLower(body)
	return !containsHTMLSignature(lower) && containsAllLower(lower, want)
}

// FreshMetadataMarkers returns the curated markers that appear in body but are
// absent from baseline (case-insensitive, order preserved). The marker lists in
// InternalSSRFTargets are already distinct, so no de-duplication is needed. The
// caller requires at least MinMetadataMarkers of them before trusting the hit, so
// one common word echoed by the application's own page cannot confirm on its own.
func FreshMetadataMarkers(body, baseline string, markers []string) []string {
	lowerBody := strings.ToLower(body)
	lowerBase := strings.ToLower(baseline)
	var out []string
	for _, mk := range markers {
		needle := strings.ToLower(mk)
		if strings.Contains(lowerBody, needle) && !strings.Contains(lowerBase, needle) {
			out = append(out, mk)
		}
	}
	return out
}

// BodyContainsAllMarkers reports whether body contains every marker in want
// (case-insensitive). Used to detect a decoy/catch-all that serves the identical
// canned content for any target.
func BodyContainsAllMarkers(body string, want []string) bool {
	if len(want) == 0 {
		return false
	}
	return containsAllLower(strings.ToLower(body), want)
}

// BodyLooksLikeHTMLPage reports whether body is an HTML document — the
// application's own page — rather than the plain-text or JSON a cloud metadata
// service returns. AWS/GCP/Alibaba metadata endpoints answer with a plain-text
// directory listing and Azure/DigitalOcean with JSON; none ever emit an HTML
// document. A metadata-looking token inside an HTML body is therefore the app
// echoing a common word (a soft-404 / SPA index fallback), not a reached endpoint.
func BodyLooksLikeHTMLPage(body string) bool {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	return containsHTMLSignature(strings.ToLower(head))
}

// containsHTMLSignature reports whether the already-lowercased s contains any HTML
// page signature.
func containsHTMLSignature(lower string) bool {
	for _, sig := range htmlPageSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// containsAllLower reports whether the already-lowercased body contains every
// marker in want (each lowercased per comparison).
func containsAllLower(lower string, want []string) bool {
	for _, mk := range want {
		if !strings.Contains(lower, strings.ToLower(mk)) {
			return false
		}
	}
	return true
}
