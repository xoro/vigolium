package browser

import (
	"errors"
	"strings"
	"testing"
)

// TestSafeRodRecoversPanic verifies that a panic raised inside the wrapped
// function (e.g. go-rod's getJSCtxID nil dereference on a cross-origin/detached
// frame) is converted into an error instead of crashing the process.
func TestSafeRodRecoversPanic(t *testing.T) {
	err := safeRod("ElementX", func() error {
		// Mimics the go-rod nil-pointer dereference at page_eval.go:350.
		var p *struct{ ContentDocument *struct{ BackendNodeID int } }
		_ = p.ContentDocument.BackendNodeID
		return nil
	})
	if err == nil {
		t.Fatal("expected an error from a recovered panic, got nil")
	}
	if !strings.Contains(err.Error(), "ElementX") {
		t.Errorf("error should name the operation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "go-rod panic") {
		t.Errorf("error should mention go-rod panic, got: %v", err)
	}
}

// TestSafeRodPassesThroughError verifies a normal (non-panic) error from the
// wrapped function is returned unchanged.
func TestSafeRodPassesThroughError(t *testing.T) {
	sentinel := errors.New("boom")
	err := safeRod("Element", func() error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected the wrapped error to pass through, got: %v", err)
	}
}

// TestSafeRodSuccess verifies the happy path returns nil.
func TestSafeRodSuccess(t *testing.T) {
	called := false
	err := safeRod("HTML", func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if !called {
		t.Error("expected fn to be invoked")
	}
}
