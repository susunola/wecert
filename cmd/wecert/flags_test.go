package main

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A contradictory flag combination must be an error at startup, not one flag silently winning
// over the other.
//
// Each of these used to be resolved by whichever branch ran first: -revoke returned before the
// logger, the dry-run branch and the reconcile loop were even read, so "-revoke x -dry-run"
// revoked; and "-once -dry-run" dry-ran, with -once never mentioned again.
func TestValidateFlagsRejectsContradictions(t *testing.T) {
	set := func(names ...string) map[string]bool {
		m := map[string]bool{}
		for _, n := range names {
			m[n] = true
		}
		return m
	}

	contradictions := []struct {
		name     string
		explicit map[string]bool
		once     bool
		dryRun   bool
		interval time.Duration
	}{
		{"-revoke with -once", set("revoke", "once"), true, false, time.Hour},
		{"-revoke with -dry-run", set("revoke", "dry-run"), false, true, time.Hour},
		{"-revoke with -log-level", set("revoke", "log-level"), false, false, time.Hour},
		{"-revoke with -interval", set("revoke", "interval"), false, false, time.Hour},
		{"-once with -dry-run", set("once", "dry-run"), true, true, time.Hour},
		{"a sub-minute daemon interval", set("interval"), false, false, 5 * time.Second},
		{"a zero daemon interval (jitter degrades it to one second)", set("interval"), false, false, 0},
	}
	for _, tc := range contradictions {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateFlags(tc.explicit, tc.once, tc.dryRun, tc.interval); err == nil {
				t.Error("a contradictory combination must be rejected, not resolved silently")
			}
		})
	}

	sane := []struct {
		name     string
		explicit map[string]bool
		once     bool
		dryRun   bool
		interval time.Duration
	}{
		{"the defaults", set(), false, false, time.Hour},
		{"-revoke alone", set("revoke"), false, false, time.Hour},
		{"-once alone", set("once"), true, false, time.Hour},
		{"-dry-run alone", set("dry-run"), false, true, time.Hour},
		// The floor only guards the daemon loop: -once never reads the interval, and rejecting
		// it there would break a one-shot invocation that copied the daemon's command line.
		{"-once ignores the interval", set("once", "interval"), true, false, 5 * time.Second},
		{"-dry-run ignores the interval", set("dry-run", "interval"), false, true, 0},
	}
	for _, tc := range sane {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateFlags(tc.explicit, tc.once, tc.dryRun, tc.interval); err != nil {
				t.Errorf("a sane combination must pass, got %v", err)
			}
		})
	}
}

// An unknown -log-level must be an error, not a silent fall back to info: the fall back ran a
// mistyped verbosity ("wran") as info with no line anywhere saying so.
func TestParseLogLevelRejectsUnknownValues(t *testing.T) {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		// Case-insensitive, as before.
		"DEBUG": slog.LevelDebug,
		"Warn":  slog.LevelWarn,
	}
	for in, want := range levels {
		got, err := parseLogLevel(in)
		if err != nil {
			t.Errorf("parseLogLevel(%q): %v", in, err)
		} else if got != want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}

	for _, bad := range []string{"wran", "verbose", ""} {
		if _, err := parseLogLevel(bad); err == nil {
			t.Errorf("parseLogLevel(%q) must be an error, not a silent fall back to info", bad)
		} else if !strings.Contains(err.Error(), bad) {
			t.Errorf("the error must echo the offending value %q, got %v", bad, err)
		}
	}
}
