package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

// This file renders findings and HTTP records as Markdown for the --markdown
// display mode on `vigolium finding` / `vigolium traffic`. Output goes to
// stdout as plain Markdown (request/response in ```http fences), so it pipes
// cleanly into a file or a viewer like `glow`.
//
// Under -S/--stateless, --compact windows the response around the finding's
// matched_at / extracted_results (or caps a record's response body), keeping
// the proof on screen without dumping a whole page. Outside --stateless,
// bodies render whole — compact-windowing of the human output is stateless-only.

// statelessEvidenceWindow is the number of characters kept on each side of the
// match when --compact windows a response body. Wider than the JSON evidence
// window (agentEvidenceWindow) because Markdown is read by a human, not budgeted
// in tokens.
const statelessEvidenceWindow = 360

// displayFindingsMarkdown renders each finding (and its linked HTTP records) as
// Markdown to stdout. Compact-windowing applies only under --stateless.
func displayFindingsMarkdown(ctx context.Context, db *database.DB, findings []*database.Finding) error {
	compact := jsonCompact && globalStateless
	// Resolve every linked record for the page in one query (not per finding),
	// mirroring the --json path's findingViews.
	byUUID := batchLoadFindingRecords(ctx, db, findings)
	for i, f := range findings {
		if i > 0 {
			fmt.Println("---")
			fmt.Println()
		}
		var records []*database.HTTPRecord
		for _, u := range f.HTTPRecordUUIDs {
			if r := byUUID[u]; r != nil {
				records = append(records, r)
			}
		}
		renderFindingMarkdown(f, records, os.Stdout, compact)
	}
	return nil
}

// displayTrafficMarkdown renders each HTTP record as Markdown to stdout.
func displayTrafficMarkdown(records []*database.HTTPRecord) error {
	compact := jsonCompact && globalStateless
	for i, rec := range records {
		if i > 0 {
			fmt.Println("---")
			fmt.Println()
		}
		renderRecordMarkdown(rec, os.Stdout, false, compact)
	}
	return nil
}

// renderFindingMarkdown writes one finding as Markdown: a severity-tagged
// heading, metadata, evidence fields, then the request and response. The
// request/response come from the linked records when present, falling back to
// the request/response stored inline on the finding.
func renderFindingMarkdown(f *database.Finding, records []*database.HTTPRecord, out io.Writer, compact bool) {
	ew := &errWriter{w: out}
	ew.printf("## [%s] %s", strings.ToUpper(f.Severity), f.ModuleName)
	if f.ModuleShort != "" {
		ew.printf(" — %s", f.ModuleShort)
	}
	ew.println()
	ew.println()

	var meta []string
	if f.ModuleID != "" {
		meta = append(meta, "**Module:** `"+f.ModuleID+"`")
	}
	if f.Confidence != "" {
		meta = append(meta, "**Confidence:** "+f.Confidence)
	}
	if f.ModuleType != "" {
		meta = append(meta, "**Type:** "+f.ModuleType)
	}
	if f.FindingSource != "" {
		meta = append(meta, "**Source:** "+f.FindingSource)
	}
	if f.CVSSScore != 0 {
		meta = append(meta, fmt.Sprintf("**CVSS:** %.1f", f.CVSSScore))
	}
	if len(meta) > 0 {
		ew.println(strings.Join(meta, " | "))
		ew.println()
	}

	if url := findingURLValue(f); url != "" {
		ew.printf("**URL:** %s\n\n", url)
	}
	if len(f.MatchedAt) > 0 {
		ew.printf("**Matched at:** %s\n\n", strings.Join(f.MatchedAt, ", "))
	}
	if f.Description != "" {
		ew.println(f.Description)
		ew.println()
	}
	if len(f.ExtractedResults) > 0 {
		ew.printf("**Extracted:** %s\n\n", strings.Join(f.ExtractedResults, ", "))
	}
	if len(f.AdditionalEvidence) > 0 {
		ew.printf("**Additional evidence:** %s\n\n", strings.Join(f.AdditionalEvidence, ", "))
	}
	if len(f.Tags) > 0 {
		ew.printf("**Tags:** %s\n\n", strings.Join(f.Tags, ", "))
	}

	req, resp := findingRequestResponse(f, records)
	// The request carries the payload — always show it whole. The response is
	// what compact windows around the match.
	writeHTTPSection(ew, "Request", req, false, nil, 0)
	needles := append(append([]string{}, f.ExtractedResults...), f.MatchedAt...)
	writeHTTPSection(ew, "Response", resp, compact, needles, agentRespBodyPreviewMax)
}

// renderRecordMarkdown writes one HTTP record as Markdown. requestOnly omits the
// response (used by `db export --format markdown`). compact caps the response
// body to a preview — records have no match needle, so there is nothing to
// window around.
func renderRecordMarkdown(rec *database.HTTPRecord, out io.Writer, requestOnly, compact bool) {
	ew := &errWriter{w: out}
	heading := fmt.Sprintf("## %s %s", rec.Method, rec.URL)
	if rec.HasResponse {
		heading += fmt.Sprintf(" → %d (%dms)", rec.StatusCode, rec.ResponseTimeMs)
	}
	ew.println(heading)
	ew.println()

	uuidShort := rec.UUID
	if len(uuidShort) > 8 {
		uuidShort = uuidShort[:8]
	}
	ew.printf("**UUID:** `%s` | **Source:** %s | **Sent:** %s\n\n",
		uuidShort, rec.Source, rec.SentAt.Format("2006-01-02 15:04:05"))

	writeHTTPSection(ew, "Request", string(rec.RawRequest), false, nil, 0)
	if !requestOnly && rec.HasResponse {
		writeHTTPSection(ew, "Response", string(rec.RawResponse), compact, nil, agentRespBodyPreviewMax)
	}
}

// findingRequestResponse picks the request/response to render for a finding,
// preferring the first linked record that carries each and falling back to the
// request/response stored inline on the finding itself.
func findingRequestResponse(f *database.Finding, records []*database.HTTPRecord) (req, resp string) {
	for _, rec := range records {
		if req == "" && len(rec.RawRequest) > 0 {
			req = string(rec.RawRequest)
		}
		if resp == "" && rec.HasResponse && len(rec.RawResponse) > 0 {
			resp = string(rec.RawResponse)
		}
	}
	if req == "" {
		req = f.Request
	}
	if resp == "" {
		resp = f.Response
	}
	return req, resp
}

// writeHTTPSection writes a "### Title" heading followed by a ```http fenced
// block. When compact is set the body is windowed (compactRawHTTP); otherwise
// the raw message is emitted whole. A blank raw message writes nothing.
func writeHTTPSection(ew *errWriter, title, raw string, compact bool, needles []string, bodyCap int) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	body := raw
	if compact {
		body = compactRawHTTP(raw, needles, bodyCap)
	}
	ew.println("### " + title)
	ew.println()
	ew.println("```http")
	ew.println(strings.TrimRight(body, "\r\n"))
	ew.println("```")
	ew.println()
}

// compactRawHTTP shrinks a raw HTTP message for compact display: headers kept
// verbatim, body windowed around the first needle (matched_at / extracted) when
// one is found, otherwise capped to bodyCap bytes. Gzip bodies are decoded so
// the window is readable text.
func compactRawHTTP(raw string, needles []string, bodyCap int) string {
	headers, body := splitHeadersBody([]byte(raw))
	if len(body) == 0 {
		return headers
	}
	bodyStr := string(maybeGunzip(body))

	if snip := evidenceSnippet(bodyStr, needles, statelessEvidenceWindow); snip != "" {
		return headers + "\r\n\r\n" + snip
	}
	if bodyCap > 0 && len(bodyStr) > bodyCap {
		return headers + "\r\n\r\n" + bodyStr[:bodyCap] +
			fmt.Sprintf("\n… (%d more bytes truncated)", len(bodyStr)-bodyCap)
	}
	return headers + "\r\n\r\n" + bodyStr
}
