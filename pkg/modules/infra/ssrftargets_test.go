package infra

import (
	"reflect"
	"testing"
)

func TestFreshMetadataMarkers(t *testing.T) {
	markers := []string{"ami-id", "instance-id", "local-hostname"}

	t.Run("all fresh", func(t *testing.T) {
		body := "ami-id: ami-0\ninstance-id: i-0\nlocal-hostname: ip-10\n"
		got := FreshMetadataMarkers(body, "", markers)
		if !reflect.DeepEqual(got, markers) {
			t.Fatalf("want %v, got %v", markers, got)
		}
	})

	t.Run("baseline suppresses already-present token", func(t *testing.T) {
		body := "ami-id: ami-0\ninstance-id: i-0\n"
		baseline := "ami-id appears in the app page too"
		got := FreshMetadataMarkers(body, baseline, markers)
		want := []string{"instance-id"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("want %v, got %v", want, got)
		}
	})

	t.Run("case-insensitive", func(t *testing.T) {
		got := FreshMetadataMarkers("AMI-ID: x\nINSTANCE-ID: y\n", "", markers)
		if len(got) != 2 {
			t.Fatalf("want 2, got %v", got)
		}
	})
}

func TestBodyContainsAllMarkers(t *testing.T) {
	body := "ami-id: x\ninstance-id: y\n"
	if !BodyContainsAllMarkers(body, []string{"ami-id", "instance-id"}) {
		t.Error("should contain all")
	}
	if BodyContainsAllMarkers(body, []string{"ami-id", "zone"}) {
		t.Error("should not contain zone")
	}
	if BodyContainsAllMarkers(body, nil) {
		t.Error("empty want must be false")
	}
}

func TestConfirmFreshMetadata(t *testing.T) {
	markers := []string{"ami-id", "instance-id", "local-hostname"}

	t.Run("plain body with cluster confirms", func(t *testing.T) {
		got, ok := ConfirmFreshMetadata("ami-id: x\ninstance-id: y\n", "", markers)
		if !ok || len(got) != 2 {
			t.Fatalf("want 2 markers + ok, got %v ok=%v", got, ok)
		}
	})

	t.Run("HTML page rejected even with a marker word", func(t *testing.T) {
		body := "<html><body><script>const h = window.location.local-hostname;</script></body></html>"
		if _, ok := ConfirmFreshMetadata(body, "", markers); ok {
			t.Fatal("HTML page must not confirm")
		}
	})

	t.Run("single marker insufficient", func(t *testing.T) {
		if _, ok := ConfirmFreshMetadata("ami-id only\n", "", markers); ok {
			t.Fatal("one marker must not confirm")
		}
	})

	t.Run("baseline-present markers do not count", func(t *testing.T) {
		body := "ami-id: x\ninstance-id: y\n"
		if _, ok := ConfirmFreshMetadata(body, "ami-id and instance-id are in the app page", markers); ok {
			t.Fatal("markers already in baseline must not confirm")
		}
	})
}

func TestMetadataBodyReproduces(t *testing.T) {
	markers := []string{"ami-id", "instance-id"}
	if !MetadataBodyReproduces("ami-id: x\ninstance-id: y\n", markers) {
		t.Error("plain body with all markers should reproduce")
	}
	if MetadataBodyReproduces("<html>ami-id instance-id</html>", markers) {
		t.Error("HTML body must not reproduce")
	}
	if MetadataBodyReproduces("ami-id only\n", markers) {
		t.Error("missing a marker must not reproduce")
	}
	if MetadataBodyReproduces("ami-id\ninstance-id\n", nil) {
		t.Error("empty want must not reproduce")
	}
}

func TestBodyLooksLikeHTMLPage(t *testing.T) {
	htmlBodies := []string{
		"<!doctype html>\n<html lang=\"en\"><head></head><body></body></html>",
		"<html><body>x</body></html>",
		"<script>const isProd = window.location.hostname === 'x';</script>",
		"<div id=\"root\"></div>",
	}
	for _, b := range htmlBodies {
		if !BodyLooksLikeHTMLPage(b) {
			t.Errorf("expected HTML for %q", b)
		}
	}

	metadataBodies := []string{
		"ami-id\ninstance-id\nlocal-hostname\n",
		`{"vmId":"abc","vmSize":"Standard_D2"}`,
		"droplet_id\nregion\ninterfaces/\n",
		"hostname\nzone\nmachine-type\n",
	}
	for _, b := range metadataBodies {
		if BodyLooksLikeHTMLPage(b) {
			t.Errorf("expected NOT-HTML for %q", b)
		}
	}
}
