package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nopLog struct{}

func (nopLog) Info(string, ...any)  {}
func (nopLog) Warn(string, ...any)  {}
func (nopLog) Error(string, ...any) {}

func testNginx(t *testing.T, reload []string, overrides map[string]string) (*Nginx, string) {
	t.Helper()
	dir := t.TempDir()
	n, err := NewNginx(NginxOptions{
		DirTemplate: filepath.Join(dir, "%s"),
		CertFile:    "fullchain.pem",
		KeyFile:     "privkey.pem",
		Reload:      reload,
		Overrides:   overrides,
	}, nopLog{})
	if err != nil {
		t.Fatalf("NewNginx: %v", err)
	}
	return n, dir
}

// First deploy writes both files and reloads; the id names the directory so a
// later resume/reclaim can find it again.
func TestNginxDeployWritesFilesAndReloads(t *testing.T) {
	n, root := testNginx(t, []string{"true"}, nil)
	id, err := n.Deploy(context.Background(), "www-example-com", "", []byte("CHAIN\n"), []byte("KEY\n"))
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	dir := filepath.Join(root, "www-example-com")
	if id != "nginx:"+dir {
		t.Errorf("id = %q, want nginx:%s", id, dir)
	}
	cert, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil || string(cert) != "CHAIN\n" {
		t.Errorf("fullchain = %q, %v", cert, err)
	}
	key, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil || string(key) != "KEY\n" {
		t.Errorf("privkey = %q, %v", key, err)
	}
	// The key is the credential: it must not be group/other readable.
	st, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("privkey.pem mode = %04o, want 0600", st.Mode().Perm())
	}
	if c, _, _ := n.Bindings(context.Background(), id); c != 1 {
		t.Errorf("Bindings = %d, want 1 (the files are the bind)", c)
	}
}

// A reload failure must still return the directory id: the files landed, and the
// caller's contract is to record that identity so the next pass resumes it
// instead of writing a second anonymous pair.
func TestNginxReloadFailureKeepsTheID(t *testing.T) {
	n, root := testNginx(t, []string{"false"}, nil)
	id, err := n.Deploy(context.Background(), "www", "", []byte("C"), []byte("K"))
	if err == nil {
		t.Fatal("a failing reload must surface")
	}
	if !strings.Contains(err.Error(), "reload") {
		t.Errorf("err should name the reload, got %q", err)
	}
	dir := filepath.Join(root, "www")
	if id != "nginx:"+dir {
		t.Errorf("id = %q on reload failure, want nginx:%s (files already landed)", id, dir)
	}
	// Resume only reloads -- the files are already there.
	n2, _ := testNginx(t, []string{"true"}, map[string]string{"www": dir})
	// copy layout: resume uses uploadedID's directory
	id2, err := n2.ResumeDeploy(context.Background(), "www", "", id)
	if err != nil {
		t.Fatalf("ResumeDeploy: %v", err)
	}
	if id2 != id {
		t.Errorf("resume id = %q, want %q", id2, id)
	}
}

// Upload is the durable half of the staged pair; DeployUploaded is reload-only.
func TestNginxStagedUploadThenDeploy(t *testing.T) {
	n, root := testNginx(t, []string{"true"}, nil)
	id, err := n.Upload(context.Background(), "api", []byte("C"), []byte("K"))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "api", "fullchain.pem")); err != nil {
		t.Fatalf("Upload must write the files before reload: %v", err)
	}
	if got, err := n.DeployUploaded(context.Background(), "api", "", id); err != nil || got != id {
		t.Fatalf("DeployUploaded = %q, %v", got, err)
	}
}

// DeployUploaded without files is not a silent success -- nginx would keep serving
// whatever it already had.
func TestNginxDeployUploadedRefusesMissingFiles(t *testing.T) {
	n, _ := testNginx(t, []string{"true"}, nil)
	if _, err := n.DeployUploaded(context.Background(), "ghost", "", "nginx:/tmp/does-not-exist-wecert"); err == nil {
		t.Fatal("missing files must fail the deploy")
	}
}

func TestNginxDeleteRemovesFiles(t *testing.T) {
	n, root := testNginx(t, []string{"true"}, nil)
	id, err := n.Upload(context.Background(), "www", []byte("C"), []byte("K"))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "www", "privkey.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("privkey should be gone, err=%v", err)
	}
	// Deleting again is not an error: the reaper revisits ids.
	if err := n.Delete(context.Background(), id); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

// An id this deployer did not mint must not be removed -- claiming success would
// make the reaper forget a real Tencent certificate.
func TestNginxDeleteRefusesForeignID(t *testing.T) {
	n, _ := testNginx(t, nil, nil)
	err := n.Delete(context.Background(), "cert-abc123")
	if err == nil {
		t.Fatal("a non-nginx id must not be deleted here")
	}
}

// Per-certificate dir override wins over the template.
func TestNginxOverrideDirectory(t *testing.T) {
	n, root := testNginx(t, []string{"true"}, map[string]string{"www": ""})
	// empty override is ignored
	if got := n.dirFor("www"); got != filepath.Join(root, "www") {
		t.Errorf("empty override should fall back, got %s", got)
	}
	n.overrides["www"] = filepath.Join(root, "special")
	if got := n.dirFor("www"); got != filepath.Join(root, "special") {
		t.Errorf("override dir = %s", got)
	}
}

// reload is argv, not a shell string: metacharacters cannot run.
func TestNginxReloadIsArgvNotShell(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	// One argv with spaces and a semicolon must fail to exec (no such file), and
	// must not be handed to `sh -c`, which would create the marker.
	n, _ := testNginx(t, []string{"systemctl reload nginx; touch " + marker}, nil)
	id, err := n.Upload(context.Background(), "x", []byte("C"), []byte("K"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DeployUploaded(context.Background(), "x", "", id); err == nil {
		t.Fatal("a single argv with spaces and ; should fail to exec (not be run by a shell)")
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("reload must not be interpreted by a shell")
	}
}
