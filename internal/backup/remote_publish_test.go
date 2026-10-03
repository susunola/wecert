package backup

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

func TestSignedUploadPublishesSignatureDespiteRetentionFailure(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.listFail = true
	src := writeSnapshot(t, t.TempDir(), snapshotName("20260101T000000.000Z"), "snapshot")
	target := s3Target(store, 1, []byte("signing-key"))
	err := Upload(context.Background(), target, src)
	if err == nil || !IsUploaded(err) {
		t.Fatalf("want uploaded retention error, got %v", err)
	}
	if err := VerifyUpload(context.Background(), target, src); err != nil {
		t.Fatalf("signed recovery point is unusable: %v", err)
	}
}

func TestSignedUploadDoesNotPruneBeforeSignaturePublication(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	old := objectKey("20250101T000000.000Z")
	store.put(old, []byte("old recovery point"))
	src := writeSnapshot(t, t.TempDir(), snapshotName("20260101T000000.000Z"), "snapshot")
	if err := os.Mkdir(src+".hmac", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Upload(context.Background(), s3Target(store, 1, []byte("key")), src); err == nil {
		t.Fatal("want signature publication error")
	}
	if !store.has(old) {
		t.Fatal("incomplete signed upload removed the previous recovery point")
	}
}

func TestSFTPStopsAfterHandshakeOnDeadlineOrCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		name := "deadline"
		if cancelEarly {
			name = "cancellation"
		}
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			ready := make(chan struct{})
			addr, known, stop := startTestSFTPServer(t, func(rw io.ReadWriteCloser) error { close(ready); <-release; return rw.Close() })
			defer stop()
			defer close(release)
			t.Setenv("WECERT_CANCEL_TEST_PASSWORD", "password")
			src := writeSnapshot(t, t.TempDir(), snapshotName("20260101T000000.000Z"), "snapshot")
			target := Target{Type: TypeSFTP, Host: addr, Username: "wecert", PasswordEnv: "WECERT_CANCEL_TEST_PASSWORD", KnownHostsFile: known, RemoteDir: "/backup", Timeout: 500 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelEarly {
				target.Timeout = 5 * time.Second
			}
			done := make(chan error, 1)
			go func() { done <- Upload(ctx, target, src) }()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("upload ended before the SFTP subsystem started: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("SFTP subsystem did not start")
			}
			if cancelEarly {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled SFTP upload reported success")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("SFTP setup outlived its deadline or cancellation")
			}
		})
	}
}
