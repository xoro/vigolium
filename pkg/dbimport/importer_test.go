package dbimport

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// newTestRepo spins up a throwaway in-memory SQLite repository, mirroring how
// the stateless JSONL loader bootstraps its scratch DB.
func newTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = ":memory:"

	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	return database.NewRepository(db)
}

// jsonlEnvelope serializes a single {"type":...,"data":...} JSONL line.
func jsonlEnvelope(t *testing.T, typ string, data any) string {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	line, err := json.Marshal(struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}{Type: typ, Data: raw})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(line)
}

// TestImportJSONLOversizedLine guards the regression that produced
// "bufio.Scanner: token too long": an http_record whose raw_response body is
// larger than the old 10MB scanner cap must still load. The reader-based loop
// grows to any line length.
func TestImportJSONLOversizedLine(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// 12MB body → ~16MB once base64-encoded onto a single JSONL line, well past
	// the 10MB cap that used to fail.
	big := database.HTTPRecord{
		UUID:        "rec-big",
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/big",
		URL:         "https://example.com/big",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-big",
		StatusCode:  200,
		HasResponse: true,
		RawResponse: bytes.Repeat([]byte("A"), 12*1024*1024),
	}
	small := database.HTTPRecord{
		UUID:        "rec-small",
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/small",
		URL:         "https://example.com/small",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-small",
		StatusCode:  200,
	}

	// No trailing newline on the final line: exercises the EOF-without-delimiter path.
	stream := jsonlEnvelope(t, "http_record", big) + "\n" +
		jsonlEnvelope(t, "http_record", small)

	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{})
	if err != nil {
		t.Fatalf("ImportJSONL on oversized line: %v", err)
	}
	if res.RecordsImported != 2 {
		t.Errorf("RecordsImported = %d, want 2", res.RecordsImported)
	}
	if res.ParseErrors != 0 {
		t.Errorf("ParseErrors = %d, want 0", res.ParseErrors)
	}
}
