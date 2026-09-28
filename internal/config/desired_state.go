package config

import (
	"fmt"
	"time"
)

// The three DesiredState modes.
//
// The difference is **who gets the final say**, not "how many files are read".
const (
	// ModeStatic: the certificates block in the config is the desired state.
	// Historical behaviour, zero risk.
	ModeStatic = "static"

	// ModeObserve: still converges on certificates, but also reads the document
	// and reports the differences.
	//
	// This is the required stage between static and enforce: it issues nothing and
	// only answers "if the document really won, what would be added and removed".
	ModeObserve = "observe"

	// ModeEnforce: the document is the desired state.
	ModeEnforce = "enforce"
)

// DesiredState configures the source of the desired state.
//
// Why the inference does not live inside wecert itself: every known pitfall in
// this system (rate limits, accidental deletion, state drift) comes from
// "judgement", which inevitably keeps changing, while the certificate
// lifecycle must stay stable. Split apart, a source failure degrades into "the
// desired state stops updating" (safe), not "domains look like they vanished"
// (disastrous).
type DesiredState struct {
	// Mode is static / observe / enforce.
	Mode string `yaml:"mode"`

	// Path is the desired-state document path. Required for observe and enforce.
	Path string `yaml:"path"`

	// MaxStaleness is how long the document may go unrefreshed before alerting,
	// default 48h.
	//
	// This is the failure mode this architecture newly introduces: after the
	// onboarding component dies, wecert keeps renewing from the old document
	// perfectly normally, everything looks fine, but no new domain ever enters.
	// Without this alert, that state persists until someone remembers to add one.
	MaxStaleness string `yaml:"maxStaleness"`

	// Parsed durations, filled in by normalize.
	MaxStalenessDur time.Duration `yaml:"-"`
}

func (d *DesiredState) normalize(hasCertificates bool) error {
	if d.Mode == "" {
		d.Mode = ModeStatic
	}

	var err error
	if d.MaxStalenessDur, err = parseDuration(d.MaxStaleness, 48*time.Hour, "desiredState.maxStaleness"); err != nil {
		return err
	}

	switch d.Mode {
	case ModeStatic:
		if d.Path != "" {
			return fmt.Errorf("desiredState.path is set but desiredState.mode is %q: "+
				"an unused path is almost always a half-finished switch to observe/enforce, "+
				"so it is rejected instead of silently ignored", ModeStatic)
		}
	case ModeObserve, ModeEnforce:
		if d.Path == "" {
			return fmt.Errorf("desiredState.mode=%q requires desiredState.path", d.Mode)
		}
	default:
		return fmt.Errorf("desiredState.mode must be %q, %q or %q, got %q",
			ModeStatic, ModeObserve, ModeEnforce, d.Mode)
	}

	if d.Mode == ModeEnforce && hasCertificates {
		return fmt.Errorf("desiredState.mode=%q but certificates is not empty: "+
			"in enforce mode the document is the single source of truth, "+
			"and leaving a stale certificates block behind means editing it would silently do nothing", d.Mode)
	}
	return nil
}
