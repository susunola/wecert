package backup

// Regression tests for the three silent failures found while covering remote.go. Each one
// describes the behaviour an operator depends on and would fail if the fix were reverted:
//
//   - a signed SFTP upload prunes twice (object, then sidecar), and retention has to count
//     the snapshot it just published on both passes -- otherwise keep=1 deletes the only
//     recovery point and keep=N keeps N-1;
//   - the signature check opens a second SFTP connection, which has to run under the
//     deadline the caller configured or a silent endpoint hangs the restore for ever;
//   - a ".uploading-" sibling is an upload in flight, not a snapshot: it sorts after the
//     name it was going to become, so treating it as one makes a restore pick a
//     half-written file and makes retention evict a real snapshot to keep the garbage.
//
// The harnesses live in remote_test.go (the S3/SFTP servers) and remote_edge_test.go (the
// fake object store and the helpers used here).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// --- A1: signed SFTP retention counts the snapshot it just published -------------

// The boundary the bug lived on: a signed upload to an empty remote with keep=1. The old
// code pruned once for the object and once for the sidecar, and on the second pass "the
// file just published" was the sidecar's name, so the snapshot looked like an old sibling
// and was deleted -- leaving a remote with nothing on it and a VerifyUpload failure in the
// log while the only recovery point was already gone.
func TestSFTPSignedRetentionKeepOneKeepsTheSnapshotItJustPublished(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	key := []byte("sftp-retention-key")
	stamp := "20260101T000000.000Z"

	target := sftpTarget(addr, knownHosts, remoteDir, 1, key)
	if err := Upload(context.Background(), target, writeSnapshot(t, dir, snapshotName(stamp), "snapshot")); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	want := []string{snapshotName(stamp), snapshotName(stamp) + ".hmac"}
	if got := directoryNames(t, remoteDir); !equalStrings(got, want) {
		t.Fatalf("remote after a keep=1 signed upload = %v, want the snapshot and its sidecar, %v", got, want)
	}
	// The pair must still verify: a snapshot without its signature is not restorable, and a
	// signature without its snapshot is an orphan.
	assertRemotePairVerifies(t, remoteDir, stamp, key)
}

// keep=N onto a remote that already holds a full set. Retention must converge on exactly
// the newest N snapshots -- not N-1, which is what the old arithmetic produced once the
// sidecar pass ran -- and each victim must take its sidecar with it, or the prefix is left
// advertising a signature for an object that no longer exists.
func TestSFTPSignedRetentionKeepsExactlyKeepSnapshots(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	key := []byte("sftp-retention-key")
	const keep = 3

	// A remote that has been receiving backups, seeded directly so the test does not depend
	// on the retention behaviour it is checking.
	older := []string{"20260101T000000.000Z", "20260102T000000.000Z", "20260103T000000.000Z"}
	for _, stamp := range older {
		body := []byte(stamp)
		if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(stamp)), body, 0o600); err != nil {
			t.Fatal(err)
		}
		sig := SignSnapshot(key, body)
		if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(stamp)+".hmac"), []byte(sig+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	newest := "20260104T000000.000Z"
	target := sftpTarget(addr, knownHosts, remoteDir, keep, key)
	if err := Upload(context.Background(), target, writeSnapshot(t, dir, snapshotName(newest), newest)); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	var want []string
	for _, stamp := range append(older[1:], newest) {
		want = append(want, snapshotName(stamp), snapshotName(stamp)+".hmac")
	}
	sort.Strings(want)
	if got := directoryNames(t, remoteDir); !equalStrings(got, want) {
		t.Fatalf("remote after keep=%d = %v, want the newest %d signed pairs, %v", keep, got, keep, want)
	}
	// The victim and its sidecar go together.
	for _, gone := range []string{snapshotName(older[0]), snapshotName(older[0]) + ".hmac"} {
		if _, err := os.Stat(filepath.Join(remoteDir, gone)); err == nil {
			t.Fatalf("%s survived retention; a victim must take its sidecar with it", gone)
		}
	}
	for _, stamp := range append(older[1:], newest) {
		assertRemotePairVerifies(t, remoteDir, stamp, key)
	}
}

// The snapshot prefix is what keeps retention inside this installation's own objects. A
// shared SFTP directory holds other installations' snapshots under names that sort before
// and after ours; none of them may be deleted by our keep policy.
func TestSFTPRetentionLeavesAnotherInstallationsSnapshotsAlone(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	foreign := []string{
		"other.db.backup-20250101T000000.000Z.db",
		"other.db.backup-20260101T000000.000Z.db",
		"other.db.backup-20270101T000000.000Z.db",
	}
	for _, name := range foreign {
		if err := os.WriteFile(filepath.Join(remoteDir, name), []byte("someone else's recovery point"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(remoteDir, name+".hmac"), []byte("their signature"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stamp := "20260101T000000.000Z"
	target := sftpTarget(addr, knownHosts, remoteDir, 1, []byte("sftp-retention-key"))
	if err := Upload(context.Background(), target, writeSnapshot(t, dir, snapshotName(stamp), "our snapshot")); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	for _, name := range foreign {
		for _, kept := range []string{name, name + ".hmac"} {
			if _, err := os.Stat(filepath.Join(remoteDir, kept)); err != nil {
				t.Fatalf("retention deleted %s from a shared directory: %v", kept, err)
			}
		}
	}
	for _, kept := range []string{snapshotName(stamp), snapshotName(stamp) + ".hmac"} {
		if _, err := os.Stat(filepath.Join(remoteDir, kept)); err != nil {
			t.Fatalf("our own upload is missing: %v", err)
		}
	}
}

// --- A2: the signature check runs under the caller's deadline --------------------

// The sidecar is read over a second SFTP connection. That connection has to be bounded by
// the timeout DownloadLatest installed, because the failure it guards against is a remote
// that accepts TCP and then says nothing -- a firewall that drops packets, a hung sshd, a
// load balancer with no backend. Dialing with context.Background() discarded the deadline
// and held the restore open for ever, with the snapshot already downloaded.
//
// The server below answers the first connection with a working SFTP subsystem and stalls
// the second, which is exactly the order the code uses: download first, then verify.
func TestSFTPRestoreSignatureCheckHonoursTheTargetTimeout(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stamp := "20260101T000000.000Z"
	body := []byte("signed snapshot")
	key := []byte("sftp-signing-key")
	if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(stamp)), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(stamp)+".hmac"), []byte(SignSnapshot(key, body)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)

	var (
		mu     sync.Mutex
		silent []net.Conn
	)
	release := make(chan struct{})
	go func() {
		served := 0
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			served++
			if served == 1 {
				go serveTestSFTPSubsystem(raw, serverConfig, serveTestSFTPRealFS)
				continue
			}
			// Accepted and never spoken to: no SSH banner, so the handshake can only end
			// at a deadline.
			mu.Lock()
			silent = append(silent, raw)
			mu.Unlock()
			go func(conn net.Conn) {
				<-release
				_ = conn.Close()
			}(raw)
		}
	}()
	// A test that hangs cannot fail. The stalled connections are closed on the way out so
	// the abandoned DownloadLatest call can end even if the assertion below already failed.
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range silent {
			_ = conn.Close()
		}
	})

	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	target := sftpTarget(listener.Addr().String(), knownHosts, remoteDir, 0, key)
	target.Timeout = 300 * time.Millisecond

	type outcome struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan outcome, 1)
	go func() {
		start := time.Now()
		_, err := DownloadLatest(context.Background(), target, dir)
		done <- outcome{err: err, elapsed: time.Since(start)}
	}()

	const bound = 5 * time.Second
	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("a server that never completes the handshake must not look like a successful restore")
		}
		if !strings.Contains(got.err.Error(), "snapshot signature") {
			t.Fatalf("DownloadLatest error = %v, want the signature step to be the one that gave up", got.err)
		}
		if got.elapsed > bound {
			t.Fatalf("DownloadLatest took %s; the 300ms target timeout must bound the signature check too", got.elapsed)
		}
		// The refused download must not leave its bytes in the directory a restore installs
		// from; the "<temp>.remotekey" bookkeeping file is a separate, pre-existing wart.
		if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
			t.Fatalf("refused restore left %v in the state directory", left)
		}
	case <-time.After(bound):
		t.Fatalf("DownloadLatest was still blocked after %s with Timeout=300ms: the signature check "+
			"is not running under the caller's context", bound)
	}
}

// --- A3: an in-flight upload is not a snapshot -----------------------------------

// uploadSFTP writes "<final>.uploading-<random>" and renames it only after Close succeeds,
// so a leftover of that shape is a half-written file. It sorts after the name it was going
// to become, so listing it as a snapshot made a restore pick it over the last complete
// snapshot sitting beside it -- and state.Restore then rejects it on integrity_check, which
// turns "the remote has a good backup" into "the restore failed".
func TestSFTPRestoreIgnoresALeftoverUploadTemp(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	complete := "20260101T000000.000Z"
	if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(complete)), []byte("complete snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	leftover := snapshotName("20260102T000000.000Z") + uploadingSuffix + "0123456789abcdef"
	if err := os.WriteFile(filepath.Join(remoteDir, leftover), []byte("half-written"), 0o600); err != nil {
		t.Fatal(err)
	}

	restored, err := DownloadLatest(context.Background(), sftpTarget(addr, knownHosts, remoteDir, 0, nil), dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "complete snapshot" {
		t.Fatalf("restored %q, want the last published snapshot (the leftover upload temp was picked)", got)
	}
}

// The other half of the same rule: retention must not count an in-flight upload against
// Keep -- but it must not delete it either. The name is random and belongs to a transfer
// another instance may be running right now.
func TestSFTPRetentionIgnoresALeftoverUploadTemp(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	for _, stamp := range []string{"20260101T000000.000Z", "20260102T000000.000Z"} {
		if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(stamp)), []byte(stamp), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	leftover := snapshotName("20260103T000000.000Z") + uploadingSuffix + "0123456789abcdef"
	if err := os.WriteFile(filepath.Join(remoteDir, leftover), []byte("half-written"), 0o600); err != nil {
		t.Fatal(err)
	}

	newest := "20260104T000000.000Z"
	target := sftpTarget(addr, knownHosts, remoteDir, 2, nil)
	if err := Upload(context.Background(), target, writeSnapshot(t, dir, snapshotName(newest), newest)); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	// The leftover still counts as a directory entry, so it is part of the expected listing:
	// what must not happen is that it occupies a Keep slot (evicting 20260102) or that it is
	// deleted underneath a transfer that may still be running.
	want := []string{snapshotName("20260102T000000.000Z"), leftover, snapshotName(newest)}
	sort.Strings(want)
	if got := directoryNames(t, remoteDir); !equalStrings(got, want) {
		t.Fatalf("remote after keep=2 with a leftover upload = %v, want the two newest snapshots and the "+
			"untouched in-flight file, %v", got, want)
	}
}

// --- helpers --------------------------------------------------------------------

func directoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// assertRemotePairVerifies checks the snapshot and the signature beside it, which is the
// property retention has to preserve: a surviving snapshot whose sidecar was deleted (or
// left behind for a snapshot that is gone) is not a recovery point.
func assertRemotePairVerifies(t *testing.T, remoteDir, stamp string, key []byte) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(remoteDir, snapshotName(stamp)))
	if err != nil {
		t.Fatalf("read snapshot %s: %v", stamp, err)
	}
	sig, err := os.ReadFile(filepath.Join(remoteDir, snapshotName(stamp)+".hmac"))
	if err != nil {
		t.Fatalf("read sidecar for %s: %v", stamp, err)
	}
	if err := VerifySnapshot(key, body, string(sig)); err != nil {
		t.Fatalf("surviving pair for %s does not verify: %v", stamp, err)
	}
}
