package backup

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestCOSUploadAndRestore exercises the AWS SDK against an HTTP S3-compatible
// endpoint. In particular, a shared prefix must not restore another instance's
// newer snapshot.
func TestCOSUploadAndRestore(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_REGION", "test-region")
	var (
		mu      sync.Mutex
		objects = map[string][]byte{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			objects[key] = body
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
			prefix := r.URL.Query().Get("prefix")
			var keys []string
			for name := range objects {
				if strings.HasPrefix(name, prefix) {
					keys = append(keys, name)
				}
			}
			sort.Strings(keys)
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")
			for _, name := range keys {
				_, _ = io.WriteString(w, "<Contents><Key>"+name+"</Key></Contents>")
			}
			_, _ = io.WriteString(w, "</ListBucketResult>")
		case r.Method == http.MethodGet:
			body, ok := objects[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	src := path.Join(dir, "state.db.backup-20260924-010203")
	if err := os.WriteFile(src, []byte("right snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := Target{Type: TypeCOS, Bucket: "bucket", Prefix: "wecert", Endpoint: server.URL, SnapshotBase: "state.db"}
	if err := Upload(context.Background(), target, src); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	mu.Lock()
	objects["wecert/other.db.backup-99999999"] = []byte("wrong snapshot")
	mu.Unlock()
	restored, err := DownloadLatest(context.Background(), target, dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "right snapshot" {
		t.Fatalf("restored %q, want current instance snapshot", got)
	}
	info, err := os.Stat(restored)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("restore file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestDownloadLatestRequiresSnapshotBase(t *testing.T) {
	_, err := DownloadLatest(context.Background(), Target{Type: TypeCOS}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "snapshot base") {
		t.Fatalf("DownloadLatest error = %v, want missing snapshot base", err)
	}
}

func TestSFTPUploadAndRestore(t *testing.T) {
	dir := t.TempDir()
	remoteDir := path.Join(dir, "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_TEST_SFTP_PASSWORD", "password")
	src := path.Join(dir, "state.db.backup-20260924-010203")
	if err := os.WriteFile(src, []byte("right snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := Target{Type: TypeSFTP, Host: addr, Username: "wecert", RemoteDir: remoteDir, PasswordEnv: "WECERT_TEST_SFTP_PASSWORD", KnownHostsFile: knownHosts, SnapshotBase: "state.db"}
	if err := Upload(context.Background(), target, src); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := os.WriteFile(path.Join(remoteDir, "other.db.backup-99999999"), []byte("wrong snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := DownloadLatest(context.Background(), target, dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "right snapshot" {
		t.Fatalf("restored %q, want current instance snapshot", got)
	}
}

func startTestSFTP(t *testing.T) (string, string, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := path.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSFTP(raw, serverConfig)
		}
	}()
	return listener.Addr().String(), knownHosts, func() {
		_ = listener.Close()
		<-done
	}
}

func serveTestSFTP(raw net.Conn, config *ssh.ServerConfig) {
	_, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		conn, requests, err := channel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			for request := range requests {
				if request.Type != "subsystem" || string(request.Payload[4:]) != "sftp" {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				server, err := sftp.NewServer(conn)
				if err == nil {
					_ = server.Serve()
					_ = server.Close()
				}
				return
			}
		}()
	}
}
