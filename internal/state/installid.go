package state

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/susunola/wecert/internal/atomicfile"
)

// installIDFileName is deliberately NOT named `state.db.*`.
//
// The generation sidecar (`state.db.generation`) is the high-water mark a hand copy of
// only `state.db` leaves behind -- that case is already detected. The remaining silent
// path is `cp state.db state.db.generation /elsewhere/` and later copying the pair
// back (or onto another machine): file and database agree, so the sidecar check stays
// quiet. This file lives in the same directory under a name a `state.db*` glob does not
// match, so the usual "back up the database" copy does not carry it. A database whose
// install_id does not match this host's file was copied as a pair, or arrived from
// another installation -- say so before the next order trusts a rate-limit ledger that
// may have moved backwards.
//
// The hole that remains is an operator who copies `install-id` along with the pair.
// That is an explicit whole-directory restore and is the accepted limitation; see
// docs/backlog.md §4.
const installIDFileName = "install-id"

// installIDPath is the host-side identity file beside the state database.
func installIDPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), installIDFileName)
}

// newInstallID mints a fresh identity. 128 bits of CSPRNG, hex-encoded: no time
// component to guess at, no hostname to leak into a backup.
func newInstallID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint install id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func loadInstallIDFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// reconcileInstallID makes the database and this host's install-id file agree, and
// warns when they cannot.
//
// Called from advanceGeneration on a locked, migrating open -- the same place the
// generation sidecar is checked -- so the two signals fire together and a supported
// `wecert -restore` (which leaves a marker) starts a new lineage instead of alarming.
func (s *Store) reconcileInstallID() error {
	dbID, err := s.readInstallID()
	if err != nil {
		return err
	}
	hostID, err := loadInstallIDFile(installIDPath(s.path))
	if err != nil {
		return fmt.Errorf("read %s: %w", installIDFileName, err)
	}

	_, restored := os.Stat(s.path + RestoreMarkerSuffix)
	if restored == nil {
		// The supported restore command is the operator's acknowledgement. Adopt the
		// host identity into the restored database (or mint one) so the next start is
		// quiet, the same way generation starts a new lineage here.
		if hostID == "" {
			hostID, err = newInstallID()
			if err != nil {
				return err
			}
		}
		if err := s.writeInstallID(hostID); err != nil {
			return err
		}
		return atomicfile.Write(installIDPath(s.path), []byte(hostID+"\n"), 0o600)
	}

	switch {
	case dbID == "" && hostID == "":
		// First open of this installation.
		id, err := newInstallID()
		if err != nil {
			return err
		}
		if err := s.writeInstallID(id); err != nil {
			return err
		}
		return atomicfile.Write(installIDPath(s.path), []byte(id+"\n"), 0o600)
	case dbID != "" && hostID == "":
		// The database arrived without this host's identity file: a copy of the
		// database (and maybe its .generation sidecar) onto a fresh machine, or a
		// directory that never had install-id. Both mean "this may not be this
		// installation's ledger".
		fmt.Fprintf(os.Stderr, "wecert: WARNING: state database %s carries install id %s but %s is missing from its directory. "+
			"The database looks like it was copied here from another installation (including the .generation sidecar, if that came too). "+
			"Either restore through `wecert -restore` (which records the restore), copy the install-id file with it deliberately, or inspect the source before issuing.\n",
			s.path, dbID, installIDFileName)
		// Adopt a fresh host identity and stamp the database: the next start is then
		// quiet about *this* copy, and a second unexpected copy alarms again.
		id, err := newInstallID()
		if err != nil {
			return err
		}
		if err := s.writeInstallID(id); err != nil {
			return err
		}
		return atomicfile.Write(installIDPath(s.path), []byte(id+"\n"), 0o600)
	case dbID != hostID:
		fmt.Fprintf(os.Stderr, "wecert: WARNING: state database %s carries install id %s but this directory's %s is %s. "+
			"The database was copied over a different installation's state (or the install-id file was). "+
			"Restore through `wecert -restore`, or inspect the source before issuing; its rate-limit ledger may be behind the CA.\n",
			s.path, dbID, installIDFileName, hostID)
		// Keep the host file as the truth and stamp it into the database, matching
		// how generation prefers the higher mark and then records it.
		return s.writeInstallID(hostID)
	default:
		return nil
	}
}

func (s *Store) readInstallID() (string, error) {
	var id string
	if err := s.db.QueryRow(`SELECT install_id FROM state_generation WHERE singleton = 1`).Scan(&id); err != nil {
		return "", fmt.Errorf("read install id: %w", err)
	}
	return strings.TrimSpace(id), nil
}

func (s *Store) writeInstallID(id string) error {
	if _, err := s.db.Exec(`UPDATE state_generation SET install_id = ? WHERE singleton = 1`, id); err != nil {
		return fmt.Errorf("record install id: %w", err)
	}
	return nil
}
