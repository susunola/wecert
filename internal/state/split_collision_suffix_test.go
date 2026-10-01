package state

import "testing"

func TestSplitCollisionSuffixOnlyAcceptsNumericTails(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"20260101T000000.000Z", "20260101T000000.000Z", true},
		{"20260101T000000.000Z~2", "20260101T000000.000Z", true},
		{"20260101T000000.000Z-1234", "20260101T000000.000Z", true},
		// Anything non-numeric after the separator is not a name we wrote.
		{"20260101T000000.000Z-before-upgrade", "20260101T000000.000Z", false},
		{"20260101T000000.000Z-manual", "20260101T000000.000Z", false},
		{"20260101T000000.000Z~", "20260101T000000.000Z", false},
	} {
		got, ok := SplitCollisionSuffix(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("SplitCollisionSuffix(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// A hand-made "backup-<stamp>-manual.db" must not count as ours: retention
// would otherwise delete the operator's own copy.
func TestIsSnapshotNameRejectsNonNumericCollisionSuffix(t *testing.T) {
	if IsSnapshotName("state.db.backup-20260101T000000.000Z-before-upgrade.db", "state.db") {
		t.Error("a non-numeric collision suffix must not look like a snapshot")
	}
	if !IsSnapshotName("state.db.backup-20260101T000000.000Z.db", "state.db") {
		t.Error("a plain snapshot name must still match")
	}
	if !IsSnapshotName("state.db.backup-20260101T000000.000Z-1234.db", "state.db") {
		t.Error("the legacy -<pid> suffix must still match")
	}
}
