package onboarding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
func LoadState(path string) (*State, error) {
	st := &State{AbsentSince: map[string]time.Time{}}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, fmt.Errorf("read onboarding state: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return st, nil
	}

	// A corrupt state file must **not** count as empty: that zeroes every grace
	// period, turning deletion from conservative into aggressive. Better to refuse.
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parse onboarding state %s: %w", path, err)
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

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".onboard-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write onboarding state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync onboarding state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close onboarding state: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod onboarding state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = ""
	return nil
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
