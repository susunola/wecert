package certsync

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/backup"
	"github.com/susunola/wecert/internal/config"
)

// DefaultPublisher is the only part of this package the ACME manager holds: it is handed the
// certificate row, not an export block, so the row's own settings are what have to reach disk. A
// version that read a global export config, or that named the directory after anything but the
// row's certificate name, would publish one certificate's private key over another's -- and the
// overwritten name is exactly the file an operator's deploy watches.
func TestDefaultPublisherPublishesUnderTheCertificateNameFromTheRow(t *testing.T) {
	dir := t.TempDir()
	cert := &config.Certificate{Name: "example-com", Export: &config.CertificateExport{LocalDir: dir}}

	if err := (DefaultPublisher{}).Publish(context.Background(), cert, []byte("chain-of-the-row"), []byte("key-of-the-row")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for name, want := range map[string]string{
		"fullchain.pem": "chain-of-the-row",
		"privkey.pem":   "key-of-the-row",
	} {
		path := filepath.Join(dir, "example-com", name)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

// Export is opt-in, and a certificate row without an export block must therefore be a silent no-op
// rather than an error: turning an absent block into a failure would fail every certificate that
// never asked for file export.
//
// The unsafe name is the point, not an accident. With no configuration there is nothing to write
// and nothing to validate against, so the nil check has to come first -- and the same name must
// still be refused the moment a destination exists, which is what the second half asserts. A nil
// block that skipped the name check for a real destination would be a traversal, not a no-op.
func TestExportWithoutAConfigurationIsANoOp(t *testing.T) {
	const unsafe = "../outside"
	if err := Export(context.Background(), nil, unsafe, []byte("chain"), []byte("key")); err != nil {
		t.Fatalf("Export with no configuration = %v, want nil: an unconfigured export has nothing to do", err)
	}

	dir := t.TempDir()
	err := Export(context.Background(), &config.CertificateExport{LocalDir: dir}, unsafe, []byte("chain"), []byte("key"))
	if err == nil {
		t.Fatal("the same name was accepted once a destination existed; the nil check must not disable the name check")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("a rejected name wrote %d entries into the export directory", len(entries))
	}
}

// The certificate name becomes a single path element under LocalDir. Anything that could steer the
// write somewhere else -- an absolute path, a parent reference, a separator -- has to be refused
// before the first byte is staged: these files include privkey.pem, so a name that escapes the
// directory the operator configured writes a private key to a place no deploy reads and, worse,
// possibly over a file that another service depends on.
func TestExportRejectsNamesThatCouldEscapeTheExportDirectory(t *testing.T) {
	for _, tc := range []struct{ name, cert string }{
		{name: "empty", cert: ""},
		{name: "current directory", cert: "."},
		{name: "parent reference", cert: "../outside"},
		{name: "separator", cert: "a/b"},
		{name: "inner parent reference", cert: "sub/../sibling"},
		{name: "absolute", cert: "/absolute"},
		{name: "leading dot slash", cert: "./relative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "exports")
			err := Export(context.Background(), &config.CertificateExport{LocalDir: dir}, tc.cert, []byte("chain"), []byte("key"))
			if err == nil {
				t.Fatalf("certificate name %q was accepted; it can only be written as one path element under %s", tc.cert, dir)
			}
			if !strings.Contains(err.Error(), "unsafe certificate export name") {
				t.Errorf("error = %v, want the unsafe-name rejection so the operator can see which name is wrong", err)
			}
			// Nothing may appear anywhere near the destination: not under the export directory and
			// not beside it, which is where a name carrying ".." would land.
			entries, readErr := os.ReadDir(base)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("a rejected name %q produced %d entries next to the export directory: %v", tc.cert, len(entries), entryNames(entries))
			}
		})
	}
}

// entryNames lists directory entry names, for failure messages that have to show what was written
// where nothing was expected.
func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// The export directory is created with owner-only permissions even when the operator names a path
// that does not exist yet, because everything below it is private key material. A directory that
// inherited 0777 from the umask would let any local account read the key the moment it lands.
func TestExportCreatesTheDestinationDirectoryOwnerOnly(t *testing.T) {
	base := t.TempDir()
	local := filepath.Join(base, "exports", "nested")
	if err := Export(context.Background(), &config.CertificateExport{LocalDir: local}, "example-com", []byte("chain"), []byte("key")); err != nil {
		t.Fatalf("Export into a directory that does not exist yet: %v", err)
	}
	out := filepath.Join(local, "example-com")
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("the certificate directory must be created beneath the configured LocalDir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("%s mode = %o, want 700: the directory only ever holds private key material", out, info.Mode().Perm())
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		fileInfo, err := os.Stat(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, fileInfo.Mode().Perm())
		}
	}
}

// The staging directory is where the two files are written and fsynced before either destination
// sees them. When it cannot be created the export must fail rather than report success: a caller
// that deploys on a nil error would activate a certificate whose key was never published.
//
// TMPDIR is pointed at a regular file, which is the portable way to make mkdtemp fail on any
// platform and for any user (no permission bits are involved, so running as root does not paper
// over it).
func TestExportFailsWhenTheStagingDirectoryCannotBeCreated(t *testing.T) {
	base := t.TempDir()
	notADir := filepath.Join(base, "regular-file")
	if err := os.WriteFile(notADir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", notADir)

	local := filepath.Join(base, "exports")
	err := Export(context.Background(), &config.CertificateExport{LocalDir: local}, "example-com", []byte("chain"), []byte("key"))
	if err == nil {
		t.Fatal("a staging directory that cannot be created must fail the export, not silently skip it")
	}
	if _, statErr := os.Stat(filepath.Join(local, "example-com")); statErr == nil {
		t.Error("nothing may be written to the destination once staging failed: the caller was told the export did not happen")
	}
}

// A destination that cannot be created -- LocalDir naming an existing regular file -- has to fail
// with the wording the operator needs, and it has to leave that file alone. Overwriting it would
// destroy something the export was never asked to touch.
func TestExportFailsWhenTheDestinationCannotBeCreated(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("please keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Export(context.Background(), &config.CertificateExport{LocalDir: blocker}, "example-com", []byte("chain"), []byte("key"))
	if err == nil {
		t.Fatal("a LocalDir that is a regular file must fail the export")
	}
	if !strings.Contains(err.Error(), "create certificate export directory") {
		t.Errorf("error = %v, want the create-directory wording so the operator knows which knob is wrong", err)
	}
	got, readErr := os.ReadFile(blocker)
	if readErr != nil {
		t.Fatalf("the file that blocked the export was removed: %v", readErr)
	}
	if string(got) != "please keep me" {
		t.Errorf("the file that blocked the export was modified: %q", got)
	}
}

// When the destination refuses the final rename the export must fail and leave no staging file
// behind: a half-written "privkey.pem.XXXX" sitting in the directory a deploy watches is worse than
// a clean failure, because the next tool that globs for keys will find it.
//
// A non-empty directory in the place of privkey.pem is the portable way to make rename fail for any
// user, root included (rename of a non-directory onto a directory is EISDIR/ENOTEMPTY, which no
// capability overrides).
func TestExportFailsAndLeavesNoStagingFileWhenTheRenameIsRefused(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "example-com")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(out, "privkey.pem")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "in-the-way"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Export(context.Background(), &config.CertificateExport{LocalDir: dir}, "example-com", []byte("chain"), []byte("key"))
	if err == nil {
		t.Fatal("a destination that refuses the rename must fail the export")
	}
	staged, globErr := filepath.Glob(filepath.Join(out, ".wecert-export-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(staged) != 0 {
		t.Errorf("a failed export left %v in the destination directory; the temporary name must be removed on every failure path", staged)
	}
	if info, statErr := os.Stat(blocker); statErr != nil || !info.IsDir() {
		t.Errorf("the path that refused the rename must be left untouched, stat = %v, %v", info, statErr)
	}
	if _, statErr := os.Stat(filepath.Join(blocker, "in-the-way")); statErr != nil {
		t.Errorf("the export removed the contents of the path it could not write over: %v", statErr)
	}
}

// The staged write itself can be refused (a destination directory the process may not write to).
// The export must report it instead of returning nil for a certificate that never reached disk.
//
// The fixture has to be shown to take effect before anything is asserted about it: this suite runs
// as root in some environments (container images that never drop privileges), where
// CAP_DAC_OVERRIDE makes a 0500 directory writable anyway and the write this test exists to refuse
// would simply succeed. Skipping is honest; asserting on a branch that was never reached is not.
func TestExportFailsWhenTheDestinationRefusesAStagedWrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "example-com")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(out, 0o700) })

	probe, err := os.CreateTemp(out, ".fixture-probe-*")
	if err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Skip("this process can write into a 0500 directory (running as root with CAP_DAC_OVERRIDE), so an unwritable destination cannot be simulated here")
	}

	if err := Export(context.Background(), &config.CertificateExport{LocalDir: dir}, "example-com", []byte("chain"), []byte("key")); err == nil {
		t.Fatal("a destination directory that refuses the staged write must fail the export")
	}
	entries, readErr := os.ReadDir(out)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused write still produced %d entries in the destination", len(entries))
	}
}

// A remote target receives both files, under a prefix that carries the certificate name, and -- when
// the operator configured a signing key -- a sidecar signature per object.
//
// The object store here is an HTTP endpoint (the same trick internal/backup's own tests use), so the
// test asserts what actually goes on the wire: the joined prefix, the two object names, their bytes,
// and that each signature is the HMAC of the bytes that were uploaded. A target that dropped the
// certificate name from the prefix would publish every certificate into one directory; one that
// uploaded unsigned objects while an hmacKeyFile is configured would defeat the whole point of
// configuring it.
func TestExportUploadsBothFilesAndTheirSignaturesToARemoteTarget(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_REGION", "test-region")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	// The target below sets no explicit credential variables, so the defaults are what has to work.
	t.Setenv("TENCENTCLOUD_SECRET_ID", "test-cos-id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "test-cos-key")

	var (
		mu      sync.Mutex
		objects = map[string][]byte{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the uploaded object: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		objects[strings.TrimPrefix(r.URL.Path, "/bucket/")] = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	const signingKey = "export-signing-key"
	keyFile := filepath.Join(t.TempDir(), "export.hmac")
	if err := os.WriteFile(keyFile, []byte(signingKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.CertificateExport{RemoteTargets: []config.BackupTarget{{
		Type: "cos", Name: "vault", Bucket: "bucket", Prefix: "certs",
		Endpoint: server.URL, HMACKeyFile: keyFile, TimeoutDur: 30 * time.Second,
	}}}
	if err := Export(context.Background(), cfg, "example-com", []byte("chain-bytes"), []byte("key-bytes")); err != nil {
		t.Fatalf("Export: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := map[string]string{
		"certs/example-com/fullchain.pem": "chain-bytes",
		"certs/example-com/privkey.pem":   "key-bytes",
	}
	for name, body := range want {
		got, ok := objects[name]
		if !ok {
			t.Fatalf("object %s was not uploaded; the certificate name has to survive into the prefix (uploaded: %v)", name, objectNames(objects))
		}
		if string(got) != body {
			t.Errorf("object %s = %q, want %q", name, got, body)
		}
		sidecar, ok := objects[name+".hmac"]
		if !ok {
			t.Fatalf("object %s has no signature sidecar; with an hmacKeyFile configured the operator believes every object is signed (uploaded: %v)", name, objectNames(objects))
		}
		if strings.TrimSpace(string(sidecar)) != backup.SignSnapshot([]byte(signingKey), got) {
			t.Errorf("the sidecar of %s does not sign the bytes that were uploaded", name)
		}
	}
	if len(objects) != 2*len(want) {
		t.Errorf("exactly the two files and their sidecars must be published, got %v", objectNames(objects))
	}
}

// A signing key that cannot be loaded has to fail the remote export -- before anything is uploaded,
// and naming both the certificate and the target. Publishing unsigned material into a bucket the
// operator configured with an hmacKeyFile is the same lie the snapshot path refuses; and with
// several targets configured, "which one" is the only thing that makes the error actionable.
func TestExportRefusesARemoteTargetWhoseSigningKeyCannotBeRead(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unsigned material was uploaded (%s %s) although the signing key could not be loaded", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()

	for _, tc := range []struct {
		name    string
		content string
		write   bool
	}{
		{name: "missing file"},
		{name: "blank file", content: "   \n", write: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := filepath.Join(t.TempDir(), "export.hmac")
			if tc.write {
				if err := os.WriteFile(keyFile, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.CertificateExport{RemoteTargets: []config.BackupTarget{{
				Type: "cos", Name: "vault", Bucket: "bucket", Endpoint: target.URL,
				HMACKeyFile: keyFile, TimeoutDur: 30 * time.Second,
			}}}
			err := Export(context.Background(), cfg, "example-com", []byte("chain"), []byte("key"))
			if err == nil {
				t.Fatal("a target whose signing key cannot be loaded must fail the export")
			}
			for _, want := range []string{"example-com", "vault"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to name %q so the operator knows which target to fix", err, want)
				}
			}
		})
	}
}

// A target type the transport does not implement must be reported, not skipped: the operator asked
// for a copy that never happened, and silently continuing would leave them believing a destination
// holds material it does not have.
func TestExportReportsAnUnknownRemoteTargetType(t *testing.T) {
	cfg := &config.CertificateExport{RemoteTargets: []config.BackupTarget{{
		Type: "ftp", Name: "legacy-nas", Host: "nas.example.com", RemoteDir: "/certs",
	}}}
	err := Export(context.Background(), cfg, "example-com", []byte("chain"), []byte("key"))
	if err == nil {
		t.Fatal("an unknown remote target type must fail the export")
	}
	for _, want := range []string{"example-com", "legacy-nas", "unknown backup target type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
}

// objectNames returns the uploaded object names in a stable order, for failure messages that have
// to show what was published when an expected object is missing.
func objectNames(objects map[string][]byte) []string {
	names := make([]string, 0, len(objects))
	for name := range objects {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
