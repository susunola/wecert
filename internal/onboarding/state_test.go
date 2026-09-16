package onboarding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A corrupt state file must fail outright, never continue as empty state: "treat as
// empty" zeroes every grace period, turning deletion from conservative into
// aggressive -- exactly what §5.3 exists to prevent.
func TestLoadStateRefusesACorruptFile(t *testing.T) {
	for _, data := range []string{
		`{"absentSince": {`,   // truncated mid-object
		`not json at all`,     // not JSON
		`[1, 2, 3]`,           // JSON, but the wrong shape
		`{"changes": "soon"}`, // right shape, wrong types
	} {
		path := filepath.Join(t.TempDir(), "onboard-state.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}

		st, err := LoadState(path)
		if err == nil {
			t.Errorf("corrupt state %q must fail, got state %+v", data, st)
			continue
		}
		if !strings.Contains(err.Error(), "parse onboarding state") {
			t.Errorf("the error must say what could not be parsed, got %v", err)
		}
	}
}

// Only genuine absence counts as empty state: a missing file (the first run has no
// baseline yet) or an empty file (a truncated write left zero bytes, which holds no
// information to misread). Anything with content that does not parse is refused --
// see TestLoadStateRefusesACorruptFile.
func TestLoadStateTreatsMissingAndEmptyFilesAsEmptyState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "onboard-state.json")
	st, err := LoadState(missing)
	if err != nil {
		t.Fatalf("a missing state file must count as empty state (the first run), got %v", err)
	}
	if st == nil || st.AbsentSince == nil || len(st.AbsentSince) != 0 {
		t.Errorf("empty state must still carry an initialised absence ledger, got %+v", st)
	}

	empty := filepath.Join(t.TempDir(), "onboard-state.json")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(empty); err != nil {
		t.Errorf("a whitespace-only state file must count as empty state, got %v", err)
	}
}
