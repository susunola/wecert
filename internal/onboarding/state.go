package onboarding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/susunola/wecert/internal/atomicfile"
	"io"
	"os"
	"sort"
	"syscall"
	"time"
)

// State is the onboarding component's own persistent state.
//
// It must live on disk, never in memory: onboarding is usually a scheduled job
// that exits when done, and "after a restart it forgot the name had been absent
// for three days" would make the deletion grace period never elapse -- a broken
// grace period means deletion turns aggressive, exactly what §5.3 guards against.
//
// Every name set uses the **expanded** form: a wildcard is listed separately as
// "*.example.com". That way "the wildcard declaration was removed" and "the
// concrete name declaration was removed" are two independent records whose grace
// periods never interfere.
type State struct {
	// AbsentSince records when each name that was present last round and missing
	// this round was first observed absent.
	AbsentSince map[string]time.Time `json:"absentSince,omitempty"`

	// LastRevision is the fingerprint of the previously written document.
	LastRevision string `json:"lastRevision,omitempty"`

	// LastNames is the expanded name set the previous desired state covered. It
	// feeds applyGrace ("who is newly absent") and, for state files written before
	// LastDeclared existed, serves one round as the fuse's fallback baseline.
	LastNames []string `json:"lastNames,omitempty"`

	// LastDeclared is the previous round's pure declaration set -- what DNS
	// actually asked for, before guards, grace carries and grouping. It is the
	// abrupt-change fuse's baseline: the fuse exists to catch upstream data loss,
	// so it must compare declarations against declarations, never against a set
	// our own grace period padded.
	LastDeclared []string `json:"lastDeclared,omitempty"`

	// Changes holds the times of recent real name-set changes, used for the quota
	// budget.
	Changes []time.Time `json:"changes,omitempty"`

	// UpdatedAt is the time of the last successful write.
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// LoadState reads the state file. A missing file counts as empty state (first run).
//
// The open is O_NONBLOCK and the file must be regular, for the same reason as the desired-state
// document: open(2) on a FIFO blocks until a writer appears, so a FIFO at the state path hung the
// onboarding run -- which already holds the cross-process lock by then, so every later run was
// blocked behind it. A symlink is refused rather than followed, because Save replaces it: reading
// through a link whose target the next write silently abandons is how two state files start to
// disagree about the grace period.
func LoadState(path string) (*State, error) {
	st := &State{AbsentSince: map[string]time.Time{}}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, fmt.Errorf("the onboarding state file %s is a symlink; refusing to follow it "+
				"-- point the state path at the real file, because saving replaces the link", path)
		}
		return nil, fmt.Errorf("read onboarding state: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat onboarding state %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("the onboarding state file %s is not a regular file (%s); refusing it",
			path, fi.Mode().Type())
	}
	// The same contract spec.LoadDocument enforces on the desired-state document, and for the
	// same reason: this file is the grace-period clock and the change ledger, so whoever can
	// rewrite it can turn deletion from conservative into aggressive. Save writes it 0600; a
	// group- or world-writable mode is refused, and so is a different owner -- the mode bits
	// say nothing about WHO the writer is (a one-off run as root leaves a file the daemon's
	// account does not own, and neither does the check above).
	//
	// The checks run against the open descriptor (f.Stat above), not a path re-stat, so the
	// mode and owner validated are the ones on the file actually being read.
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("the onboarding state file %s is group- or world-writable (%04o); "+
			"whoever can write it can reset the grace-period clock and the change budget", path, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("the onboarding state file %s is owned by uid %d but this process runs as uid %d; "+
			"whoever owns the file can rewrite the grace-period clock", path, st.Uid, os.Geteuid())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read onboarding state: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return st, nil
	}

	// A corrupt state file must **not** count as empty: that zeroes every grace
	// period, turning deletion from conservative into aggressive. Better to refuse.
	// Unknown fields are refused for the same reason spec.LoadDocument sets
	// KnownFields on the document: a misspelled or renamed field must blow up rather
	// than be silently dropped, or a grace clock the operator believes is running is
	// not.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(st); err != nil {
		return nil, fmt.Errorf("parse onboarding state %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse onboarding state %s: trailing data after the state object", path)
	}
	if st.AbsentSince == nil {
		st.AbsentSince = map[string]time.Time{}
	}
	return st, nil
}

// Save writes the state file back atomically.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode onboarding state: %w", err)
	}
	data = append(data, '\n')

	// 0600: the file names the domains this deployment serves, and the grace-period clock that
	// decides when one is dropped.
	return atomicfile.Write(path, data, 0o600)
}

// MarkPresent clears a name's absence marker. The name is back, so the grace
// period must reset.
func (s *State) MarkPresent(name string) {
	delete(s.AbsentSince, name)
}

// MarkAbsent records a name as absent and returns the **earliest** time it was
// observed absent, plus whether this call created the record.
//
// The earliest time is kept rather than refreshed because the grace period asks
// "how long has it been absent", not "when did we last see it absent".
func (s *State) MarkAbsent(name string, now time.Time) (since time.Time, isNew bool) {
	if prev, ok := s.AbsentSince[name]; ok {
		return prev, false
	}
	s.AbsentSince[name] = now
	return now, true
}

// RecordChange records one name-set change that really happened.
func (s *State) RecordChange(now time.Time) {
	s.Changes = append(s.Changes, now)
}

// ChangesWithin returns how many set changes happened within window, dropping
// expired entries on the way.
func (s *State) ChangesWithin(window time.Duration, now time.Time) int {
	cutoff := now.Add(-window)
	kept := s.Changes[:0]
	n := 0
	for _, t := range s.Changes {
		if t.Before(cutoff) {
			continue
		}
		kept = append(kept, t)
		n++
	}
	s.Changes = kept
	return n
}

// LastNameSet returns the previous name set as a lookup map, for easy comparison.
func (s *State) LastNameSet() map[string]bool {
	out := make(map[string]bool, len(s.LastNames))
	for _, n := range s.LastNames {
		out[n] = true
	}
	return out
}

// SetLastNames stores this round's name set, in stable order so diffs stay
// readable.
func (s *State) SetLastNames(names []string) {
	cp := append([]string(nil), names...)
	sort.Strings(cp)
	s.LastNames = cp
}

// LastDeclaredNameSet returns the previous round's declaration name set as a
// lookup map, for the abrupt-change fuse.
//
// State files written before this field existed have no LastDeclared; falling
// back to the covered set keeps the fuse's old baseline for exactly one round
// instead of disabling it (or false-firing it) until the next successful write.
func (s *State) LastDeclaredNameSet() map[string]bool {
	if len(s.LastDeclared) == 0 {
		return s.LastNameSet()
	}
	out := make(map[string]bool, len(s.LastDeclared))
	for _, n := range s.LastDeclared {
		out[n] = true
	}
	return out
}

// SetLastDeclared stores this round's declaration name set, in stable order so
// diffs stay readable.
func (s *State) SetLastDeclared(names []string) {
	cp := append([]string(nil), names...)
	sort.Strings(cp)
	s.LastDeclared = cp
}
