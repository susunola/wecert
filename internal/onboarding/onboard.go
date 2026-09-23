// Package onboarding is the "infer intent" half.
//
// It enumerates declarations, applies the grouping policy and the various fuses,
// and finally writes a desired-state document. wecert only reads that document and
// never infers anything.
//
// The boundary is deliberate: every known pitfall in this system (rate limits,
// accidental deletion, state drift) comes from "judgement", and judgement logic
// inevitably changes again and again -- new sources, tuned thresholds, fixed edge
// cases. Certificate lifecycle must stay stable, so inference has to live in its
// own component and be disposable and rewritable without affecting issuance.
//
// The five invariants that must never break, mapped to their code:
//
//	5.1 source failure ≠ name gone    → the sourceErr branch in run.gather
//	5.2 abrupt desired-state fuse     → run.fuse
//	5.3 deletion conservative by an order of magnitude
//	                                  → grace period and reference check in run.resolve
//	5.4 quota fuse                    → run.budget
//	5.5 explicit authorization        → Declaration itself + Options.Allowlist
package onboarding

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
)

// Report disposition modes.
const (
	DefaultDropThreshold = 0.30
	DefaultGracePeriod   = 24 * time.Hour
	DefaultBudgetWindow  = 7 * 24 * time.Hour
	DefaultBudget        = 25
)

// Onboarder evaluates sources into a desired state.
func New(src Sources, opts Options, log *slog.Logger) (*Onboarder, error) {
	if src.Declarations == nil {
		return nil, errors.New("onboarding: a declaration source is required")
	}
	if opts.DocumentPath == "" {
		return nil, errors.New("onboarding: DocumentPath is required")
	}
	// Commit writes the document first and the state file second, so the same path for both
	// means the round finishes by replacing the desired-state document with onboarding's own
	// state -- the next round then cannot parse what it reads and the whole round is refused.
	// It is one typo away (a copy-pasted -state flag), so refuse it here where the mistake is
	// still obvious, rather than after the document is gone.
	if opts.StatePath != "" && filepath.Clean(opts.StatePath) == filepath.Clean(opts.DocumentPath) {
		return nil, fmt.Errorf("onboarding: StatePath and DocumentPath are the same file (%q); "+
			"the state file is written after the document, so this round would overwrite the "+
			"desired-state document with onboarding's own state", opts.DocumentPath)
	}
	if opts.Profile == "" {
		opts.Profile = config.ProfileClassic
	}
	if !config.ValidProfile(opts.Profile) {
		// A CLI -profile/-keytype flag lands in Options directly, bypassing the validation the
		// config file and the declaration parser both apply. A typo then produced a round that
		// reported mode="written" with a certificate count while Commit failed and nothing reached
		// the document -- the same "written but nothing on disk" shape the config path already
		// refuses.
		return nil, fmt.Errorf("onboarding: unknown profile %q (want %s/%s/%s)",
			opts.Profile, config.ProfileClassic, config.ProfileTLSServer, config.ProfileShortLived)
	}
	if opts.KeyType == "" {
		opts.KeyType = config.KeyTypeECDSAP256
	}
	if !config.ValidKeyType(opts.KeyType) {
		return nil, fmt.Errorf("onboarding: unknown keyType %q (want %s/%s)",
			opts.KeyType, config.KeyTypeECDSAP256, config.KeyTypeRSA2048)
	}
	// 0 means "use the default" for each knob below, but a NEGATIVE value is a typo, not
	// "unset": the config layer rejects the same values (config.Onboarding.normalize), and
	// silently substituting a default for a value the operator explicitly typed leaves them
	// believing a guard is tuned when it is not.
	if opts.MaxNames < 0 {
		return nil, fmt.Errorf("onboarding: MaxNames must not be negative, got %d (0 means the default of 25)", opts.MaxNames)
	}
	if opts.MaxNames == 0 {
		opts.MaxNames = 25 // Aligned with tlsserver so a future profile switch needs no redesign.
	}
	if opts.DropThreshold < 0 {
		return nil, fmt.Errorf("onboarding: DropThreshold must not be negative, got %v (0 means the default %.2f)",
			opts.DropThreshold, DefaultDropThreshold)
	}
	if opts.DropThreshold == 0 {
		opts.DropThreshold = DefaultDropThreshold
	} else if math.IsNaN(opts.DropThreshold) || opts.DropThreshold >= 1 {
		// Mirror the config layer's [0,1) check: a CLI -drop-threshold flag reaches
		// Options directly, bypassing that validation, and a percentage written as
		// `30` would silently disable the abrupt-change fuse this guard exists for.
		//
		// NaN is rejected explicitly: every comparison against it is false, so it
		// satisfies this bound and the `<= 0` default above alike and would otherwise
		// pass straight through.
		return nil, fmt.Errorf(
			"onboarding: DropThreshold is a fraction in [0,1): got %v "+
				"(a value of 1 or more can never be exceeded, so the abrupt-change fuse would never fire)",
			opts.DropThreshold)
	}
	if opts.GracePeriod < 0 {
		return nil, fmt.Errorf("onboarding: GracePeriod must not be negative, got %s (0 means the default %s)",
			opts.GracePeriod, DefaultGracePeriod)
	}
	if opts.GracePeriod == 0 {
		opts.GracePeriod = DefaultGracePeriod
	}
	if opts.BudgetWindow < 0 {
		return nil, fmt.Errorf("onboarding: BudgetWindow must not be negative, got %s (0 means the default %s)",
			opts.BudgetWindow, DefaultBudgetWindow)
	}
	if opts.BudgetWindow == 0 {
		opts.BudgetWindow = DefaultBudgetWindow
	}
	if opts.Budget < 0 {
		return nil, fmt.Errorf("onboarding: Budget must not be negative, got %d (0 means the default %d)",
			opts.Budget, DefaultBudget)
	}
	if opts.Budget == 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if src.Rules == nil {
		// The deletion path then never fires: the reference check cannot run, so
		// every grace-expired name is carried forever. That is survivable (names
		// accumulate, nothing breaks), but nobody should discover it from a report
		// months later.
		log.Warn("no CLB rule source is configured: the deletion reference check cannot run, " +
			"so no name will ever be removed once declared")
	}

	// Normalize the allowlist to registered domains too, so nobody writes
	// "www.example.com" expecting it to match all of example.com.
	if len(opts.Allowlist) > 0 {
		// Copy first: rewriting the caller's slice in place (and then sorting it) mutated
		// the config object the caller still holds.
		allow := make([]string, len(opts.Allowlist))
		for i, a := range opts.Allowlist {
			allow[i] = group.RegisteredDomain(strings.ToLower(strings.TrimSpace(a)))
		}
		// allowed() looks entries up with sort.SearchStrings, so this slice has to
		// be sorted. Sorting at the call site is not enough: normalising each entry
		// to its registered domain can reorder it (a.example.com -> example.com),
		// and an unsorted slice makes the binary search miss entries that really
		// are on the allowlist -- which silently drops names from certificates.
		sort.Strings(allow)
		opts.Allowlist = allow
	}
	return &Onboarder{src: src, opts: opts, log: log}, nil
}

// Report is the complete result of one onboarding round, and the human-facing copy.
