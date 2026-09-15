package acme

import (
	"testing"
	"time"
)

func TestParseOrderExpiresEmptyUsesFallback(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got, err := parseOrderExpires("", now)
	if err != nil {
		t.Fatalf("empty expires should not error: %v", err)
	}
	want := now.Add(defaultOrderTTL)
	if !got.Equal(want) {
		t.Errorf("empty expires = %s, want fallback %s", got, want)
	}
}

func TestParseOrderExpiresRFC3339(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	raw := "2026-09-22T00:00:00Z"
	got, err := parseOrderExpires(raw, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestParseOrderExpiresGarbageUsesFallback(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got, err := parseOrderExpires("not-a-timestamp", now)
	if err == nil {
		t.Fatal("expected error for garbage expires")
	}
	if !got.Equal(now.Add(defaultOrderTTL)) {
		t.Errorf("garbage expires should still return fallback, got %s", got)
	}
}
