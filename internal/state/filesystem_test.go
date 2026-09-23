package state

import (
	"errors"
	"strings"
	"testing"
)

func TestOpenRefusesUnsafeFilesystem(t *testing.T) {
	old := unsafeFilesystem
	t.Cleanup(func() { unsafeFilesystem = old })
	unsafeFilesystem = func(string) (string, error) { return "NFS", nil }

	_, err := Open(t.TempDir() + "/state.db")
	if err == nil || !strings.Contains(err.Error(), "NFS") || !strings.Contains(err.Error(), "local storage") {
		t.Fatalf("Open error = %v, want actionable NFS refusal", err)
	}
}

func TestOpenReportsFilesystemStatFailure(t *testing.T) {
	old := unsafeFilesystem
	t.Cleanup(func() { unsafeFilesystem = old })
	unsafeFilesystem = func(string) (string, error) { return "", errors.New("mount gone") }

	_, err := Open(t.TempDir() + "/state.db")
	if err == nil || !strings.Contains(err.Error(), "mount gone") {
		t.Fatalf("Open error = %v, want filesystem-stat failure", err)
	}
}
