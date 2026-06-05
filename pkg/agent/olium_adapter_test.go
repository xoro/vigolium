package agent

import (
	"strings"
	"sync"
	"testing"
)

// TestUniqueTranscriptNameCleanFirstUse verifies the first transcript for a
// (sessionDir, template) pair gets the clean name and subsequent ones in the
// same dir are suffixed so concurrent same-template phases never collide.
func TestUniqueTranscriptNameCleanFirstUse(t *testing.T) {
	dir := "/tmp/sess-" + t.Name()
	if got := uniqueTranscriptName(dir, "plan"); got != "transcript-plan.jsonl" {
		t.Fatalf("first use = %q, want transcript-plan.jsonl", got)
	}
	if got := uniqueTranscriptName(dir, "plan"); got != "transcript-plan-2.jsonl" {
		t.Fatalf("second use = %q, want transcript-plan-2.jsonl", got)
	}
	if got := uniqueTranscriptName(dir, "plan"); got != "transcript-plan-3.jsonl" {
		t.Fatalf("third use = %q, want transcript-plan-3.jsonl", got)
	}
	// A different template in the same dir resets to a clean name.
	if got := uniqueTranscriptName(dir, "triage"); got != "transcript-triage.jsonl" {
		t.Fatalf("new template = %q, want transcript-triage.jsonl", got)
	}
	// A different session dir is independent — separate runs stay clean.
	if got := uniqueTranscriptName(dir+"-other", "plan"); got != "transcript-plan.jsonl" {
		t.Fatalf("different dir = %q, want transcript-plan.jsonl", got)
	}
}

// TestUniqueTranscriptNameEmptyTemplate covers the inline (no-template) case.
func TestUniqueTranscriptNameEmptyTemplate(t *testing.T) {
	dir := "/tmp/sess-" + t.Name()
	if got := uniqueTranscriptName(dir, ""); got != "transcript-inline.jsonl" {
		t.Fatalf("empty template = %q, want transcript-inline.jsonl", got)
	}
	if got := uniqueTranscriptName(dir, "a/b c.."); !strings.HasPrefix(got, "transcript-a-b-") {
		t.Fatalf("unsafe template not sanitized: %q", got)
	}
}

// TestUniqueTranscriptNameConcurrentNoCollision proves concurrent calls for
// one (dir, template) pair hand out distinct filenames — the property that
// keeps swarm plan batches from corrupting one shared transcript file.
func TestUniqueTranscriptNameConcurrentNoCollision(t *testing.T) {
	dir := "/tmp/sess-" + t.Name()
	const n = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := uniqueTranscriptName(dir, "plan")
			mu.Lock()
			seen[name]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("expected %d distinct names, got %d (duplicates corrupt transcripts)", n, len(seen))
	}
}
