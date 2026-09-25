package onboarding

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// baseOptions fills every field New validates before the policy knobs, so a test for one
// knob fails for that knob alone and not for an unrelated missing field.
func baseOptions(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	return Options{
		DocumentPath: filepath.Join(dir, "desired-state.yaml"),
		StatePath:    filepath.Join(dir, "onboard-state.json"),
		ReportPath:   filepath.Join(dir, "report.json"),
		Generator:    "wecert-onboard/test",
	}
}

// 0 means "use the default", but a negative value is a typo, not "unset": the config layer
// rejects the same values (config.Onboarding.normalize), and a CLI flag lands in Options
// directly, bypassing that validation. Silently substituting the default leaves the
// operator believing a guard was tuned when it was not.
func TestNewRejectsNegativePolicyValues(t *testing.T) {
	src := Sources{Declarations: &fakeDeclarations{}, Rules: &fakeRules{}}

	cases := []struct {
		knob   string
		mutate func(*Options)
	}{
		{"MaxNames", func(o *Options) { o.MaxNames = -5 }},
		{"DropThreshold", func(o *Options) { o.DropThreshold = -0.1 }},
		{"GracePeriod", func(o *Options) { o.GracePeriod = -time.Hour }},
		{"BudgetWindow", func(o *Options) { o.BudgetWindow = -time.Hour }},
		{"Budget", func(o *Options) { o.Budget = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.knob, func(t *testing.T) {
			opts := baseOptions(t)
			tc.mutate(&opts)
			_, err := New(src, opts, testLogger())
			if err == nil {
				t.Fatalf("a negative %s must be rejected, not silently defaulted", tc.knob)
			}
			if !strings.Contains(err.Error(), tc.knob) {
				t.Errorf("the error must name the knob, got %v", err)
			}
		})
	}

	// The control: zero values still mean "use the default", so the tests above cannot be
	// satisfied by rejecting everything.
	if _, err := New(src, baseOptions(t), testLogger()); err != nil {
		t.Errorf("all-zero policy knobs must keep meaning \"use the defaults\", got %v", err)
	}
}

// New normalises the allowlist (registered-domain form, sorted) but must do it on a copy:
// the slice belongs to the caller -- rewriting and sorting it in place mutated the config
// object the caller still holds.
func TestNewDoesNotMutateTheCallersAllowlist(t *testing.T) {
	allow := []string{"WWW.Example.com ", "a.co.uk", "c.example.org"}
	original := append([]string(nil), allow...)

	opts := baseOptions(t)
	opts.Allowlist = allow
	ob, err := New(Sources{Declarations: &fakeDeclarations{}, Rules: &fakeRules{}}, opts, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := range original {
		if allow[i] != original[i] {
			t.Fatalf("the caller's allowlist was rewritten in place: %v -> %v", original, allow)
		}
	}

	// The normalised copy still has to be the one the onboarder uses: entries normalise to
	// their registered domains and come out sorted, so the binary search in allowed() can
	// find them.
	want := []string{"a.co.uk", "example.com", "example.org"}
	got := ob.opts.Allowlist
	if len(got) != len(want) {
		t.Fatalf("normalised allowlist = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalised allowlist = %v, want %v (registered-domain form, sorted)", got, want)
		}
	}
}

// The constructor's keyType message must list every value ValidKeyType accepts, like the
// declaration parser does (declaration.go): naming only some of them sends the operator fixing
// a typo with a wrong picture of what is legal.
func TestNewRejectsAnUnknownKeyTypeNamingEveryValidValue(t *testing.T) {
	opts := baseOptions(t)
	opts.KeyType = "rsa-2048" // a plausible typo; the real value is rsa2048
	_, err := New(Sources{Declarations: &fakeDeclarations{}, Rules: &fakeRules{}}, opts, testLogger())
	if err == nil {
		t.Fatal("an unknown keyType must be rejected")
	}
	for _, kt := range []string{config.KeyTypeECDSAP256, config.KeyTypeECDSAP384, config.KeyTypeRSA2048, config.KeyTypeRSA4096} {
		if !strings.Contains(err.Error(), kt) {
			t.Errorf("the error must list %q as a valid keyType, got %v", kt, err)
		}
	}

	// The control: every listed value must really be accepted.
	for _, kt := range []string{config.KeyTypeECDSAP256, config.KeyTypeECDSAP384, config.KeyTypeRSA2048, config.KeyTypeRSA4096} {
		opts := baseOptions(t)
		opts.KeyType = kt
		if _, err := New(Sources{Declarations: &fakeDeclarations{}, Rules: &fakeRules{}}, opts, testLogger()); err != nil {
			t.Errorf("a valid keyType %q must be accepted, got %v", kt, err)
		}
	}
}
