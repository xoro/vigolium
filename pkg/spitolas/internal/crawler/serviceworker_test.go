package crawler

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestServiceWorkerPrimeScriptFormats(t *testing.T) {
	// The template carries exactly one %d (the asset cap) and no stray verbs, so
	// formatting must not produce a %!(error) artifact.
	script := fmt.Sprintf(serviceWorkerPrimeScript, 123)

	if strings.Contains(script, "%!") {
		t.Fatalf("script formatting produced an error artifact:\n%s", script)
	}
	if !strings.Contains(script, "const MAX = 123;") {
		t.Errorf("script missing injected cap; got:\n%s", script)
	}
	if !strings.HasPrefix(script, "(async () => {") {
		t.Errorf("script should be a self-invoking async function")
	}
	// Core discovery sources must be present, across all supported frameworks.
	for _, want := range []string{
		"getRegistrations",
		"location.origin",
		// Angular
		"ngsw.json",
		"ngsw-worker.js",
		"assetGroups",
		"hashTable",
		// generic PWA
		"firebase-messaging-sw.js",
		// React (CRA)
		"asset-manifest.json",
		"entrypoints",
		"data.files",
		// Nuxt
		"_nuxt/builds/latest.json",
		"prerendered",
		// Workbox
		"revision",
		// Well-known-name guesses are gated behind a PWA / SPA signal (the gate's
		// position is asserted separately below).
		"pwaSignal",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing expected token %q", want)
		}
	}

	// The well-known filename guesses must sit inside the pwaSignal gate, not
	// before it — otherwise plain static sites get probed with a dozen 404s.
	gate := strings.Index(script, "if (pwaSignal) {")
	guess := strings.Index(script, "'asset-manifest.json'")
	if gate < 0 || guess < 0 || guess < gate {
		t.Errorf("well-known-name guesses must be gated behind pwaSignal (gate=%d, guess=%d)", gate, guess)
	}
}

func TestPrimeServiceWorkerAssetsGuards(t *testing.T) {
	// nil page must be a safe no-op regardless of config.
	cfgOn, err := config.New("https://example.com/")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cOn := &Crawler{config: cfgOn}
	cOn.primeServiceWorkerAssets(context.Background(), nil) // must not panic

	// Disabled config is also a no-op (and reaching the nil-page check is fine).
	cfgOff, _ := config.New("https://example.com/")
	cfgOff.ServiceWorkerPriming = false
	cOff := &Crawler{config: cfgOff}
	cOff.primeServiceWorkerAssets(context.Background(), nil) // must not panic
}

func TestServiceWorkerConfigDefaults(t *testing.T) {
	cfg, err := config.New("https://example.com/")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	if !cfg.ServiceWorkerPriming {
		t.Error("ServiceWorkerPriming should default to true")
	}
	if cfg.ServiceWorkerMaxAssets <= 0 {
		t.Errorf("ServiceWorkerMaxAssets should default > 0, got %d", cfg.ServiceWorkerMaxAssets)
	}
}
