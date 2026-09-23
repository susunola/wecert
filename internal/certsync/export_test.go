package certsync

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/susunola/wecert/internal/config"
)

func TestExportWritesPrivateMaterialWithRestrictedPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := Export(context.Background(), &config.CertificateExport{LocalDir: dir}, "example-com", []byte("chain"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"fullchain.pem": "chain", "privkey.pem": "key"} {
		path := filepath.Join(dir, "example-com", name)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
}

func TestExportRejectsUnsafeCertificateName(t *testing.T) {
	if err := Export(context.Background(), &config.CertificateExport{LocalDir: t.TempDir()}, "../outside", nil, nil); err == nil {
		t.Fatal("unsafe name must be rejected")
	}
}
