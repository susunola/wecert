package backup

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"

	"github.com/susunola/wecert/internal/state"
)

// A remote restore has to recognise the objects this deployment uploaded.
//
// Snapshots are named "<state base>-<short path hash>.backup-<stamp>.db" (see
// state.SnapshotIdentity), and an upload keeps the file's own name as the object key. The download
// side used to list under "<base>.backup-", a prefix no upload ever wrote, so `-restore remote:x`
// reported "no snapshots found" over a bucket holding its own recovery points -- remote disaster
// recovery was impossible and the error named the wrong cause.
//
// This is the end-to-end shape of the mistake, with the real store names: the store writes the
// snapshot, Upload publishes it, DownloadLatest has to fetch it back.
func TestRemoteDownloadFindsTheSnapshotTheStoreActuallyWrote(t *testing.T) {
	s3TestEnv(t)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.Snapshot(dir, 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The premise: the file on disk is not "<base>.backup-...", so a listing under that prefix
	// cannot see it.
	if base := filepath.Base(source); !strings.HasPrefix(base, fakeBase+"-") {
		t.Fatalf("snapshot %q does not carry the store identity: this test no longer tests what it "+
			"was written for", base)
	}

	fake := newFakeS3Store(t)
	target := s3Target(fake, 3, nil)
	target.SnapshotIdentity = state.SnapshotIdentity(statePath)
	if err := Upload(context.Background(), target, source); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	got, err := DownloadLatest(context.Background(), target, dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v\nThis is the remote restore path: a deployment that cannot find "+
			"its own uploads has no off-host recovery at all.", err)
	}
	defer os.Remove(got)
	if filepath.Base(got) == filepath.Base(source) {
		t.Fatalf("download wrote to the snapshot's own name %q; it must land in a temp file", got)
	}
	want, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(downloaded) != string(want) {
		t.Errorf("downloaded %d bytes, want the %d bytes of %s", len(downloaded), len(want), source)
	}
}

// The pre-hash naming generation is still accepted, because an upgrade must not strand the
// recovery points the previous build uploaded -- the same reason the state package recognises both
// forms locally.
func TestRemoteDownloadStillAcceptsThePreHashSnapshotName(t *testing.T) {
	s3TestEnv(t)

	fake := newFakeS3Store(t)
	legacy := fakeBase + ".backup-20260101T000000.000Z.db"
	fake.put(fakePrefix+"/"+legacy, []byte("legacy snapshot"))

	target := s3Target(fake, 3, nil)
	target.SnapshotIdentity = "state.db-012345" // a hash this deployment would have today
	dir := t.TempDir()
	got, err := DownloadLatest(context.Background(), target, dir)
	if err != nil {
		t.Fatalf("a snapshot uploaded before the hashed naming must still restore: %v", err)
	}
	defer os.Remove(got)
	body, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "legacy snapshot" {
		t.Errorf("downloaded %q, want the legacy object's bytes", body)
	}
}

// And another deployment's snapshots stay invisible: the identity is what keeps two installations
// with the same database filename from restoring (or pruning) each other's objects.
func TestRemoteDownloadIgnoresAnotherDeploymentsSnapshots(t *testing.T) {
	s3TestEnv(t)

	fake := newFakeS3Store(t)
	fake.put(fakePrefix+"/state.db-aaaaaa.backup-20260101T000000.000Z.db", []byte("theirs"))
	fake.put(fakePrefix+"/state.db-bbbbbb.backup-20260102T000000.000Z.db", []byte("theirs too"))

	target := s3Target(fake, 3, nil)
	target.SnapshotIdentity = "state.db-cccccc"
	if _, err := DownloadLatest(context.Background(), target, t.TempDir()); err == nil {
		t.Fatal("a deployment must not restore a snapshot that belongs to another identity")
	}
}

// The same identity rule applies to the SFTP listing, which has no server-side prefix to lean on:
// it reads the directory and filters, so the filter is the whole contract.
func TestSFTPDownloadUsesTheStoreIdentityWhenItIsGiven(t *testing.T) {
	files := sftp.InMemHandler()
	addr, knownHosts, stop := startTestSFTPServer(t, func(conn io.ReadWriteCloser) error {
		return serveInMemSFTP(conn, files)
	})
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.Snapshot(dir, 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	target := sftpTarget(addr, knownHosts, "/backup", 3, nil)
	target.SnapshotIdentity = state.SnapshotIdentity(statePath)
	if err := Upload(context.Background(), target, source); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	// Another deployment's snapshot lands in the same directory and sorts newer, so a listing that
	// ignored the identity would restore it instead.
	foreign := writeSnapshot(t, dir, "state.db-ffffff"+snapshotNameSuffix+"20990101T000000.000Z.db", "theirs")
	if err := Upload(context.Background(), target, foreign); err != nil {
		t.Fatalf("Upload (foreign name): %v", err)
	}

	got, err := DownloadLatest(context.Background(), target, dir)
	if err != nil {
		t.Fatalf("DownloadLatest over SFTP: %v", err)
	}
	defer os.Remove(got)
	body, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(want) {
		t.Errorf("restored %d bytes, want this deployment's %d-byte snapshot: an object from another "+
			"identity sorts newer and must be ignored", len(body), len(want))
	}
}
