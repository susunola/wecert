package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/susunola/wecert/internal/atomicfile"
)

const generationSuffix = ".generation"

// advanceGeneration records that this locked, migrated database has become the
// current truth.  A snapshot contains an older generation; if it is copied over
// state.db by hand, the durable sidecar remains ahead and the next start says so.
// The supported restore command writes its own marker, so it is not a false alarm.
func (s *Store) advanceGeneration() error {
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO state_generation(singleton, generation) VALUES (1, 0)`); err != nil {
		return fmt.Errorf("initialise state generation: %w", err)
	}
	if _, err := s.db.Exec(`UPDATE state_generation SET generation = generation + 1 WHERE singleton = 1`); err != nil {
		return fmt.Errorf("advance state generation: %w", err)
	}
	var generation int64
	if err := s.db.QueryRow(`SELECT generation FROM state_generation WHERE singleton = 1`).Scan(&generation); err != nil {
		return fmt.Errorf("read state generation: %w", err)
	}
	previous, present := loadGeneration(s.path + generationSuffix)
	_, restored := os.Stat(s.path + RestoreMarkerSuffix)
	if restored == nil {
		// The command's restore marker is the explicit operator acknowledgement.
		// Start a new lineage instead of preserving the old high-water mark forever.
		previous = 0
		present = false
	}
	if present && previous > generation {
		fmt.Fprintf(os.Stderr, "wecert: WARNING: state database %s generation is %d but the last seen generation was %d; it appears to have been restored or copied over outside `wecert -restore`. Its rate-limit ledger may be behind the CA. Restore through the command once, or inspect the source before issuing.\n", s.path, generation, previous)
	}
	if previous > generation {
		generation = previous
	}
	if err := atomicfile.Write(s.path+generationSuffix, []byte(strconv.FormatInt(generation, 10)+"\n"), 0o600); err != nil {
		return fmt.Errorf("record state generation: %w", err)
	}
	return nil
}

func loadGeneration(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil && v >= 0
}
