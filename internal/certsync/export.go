// Package certsync publishes issued certificate material to explicit operator
// destinations. It is deliberately separate from cloud deployment: a failed
// copy must never undo an issued, already-live certificate.
package certsync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/susunola/wecert/internal/backup"
	"github.com/susunola/wecert/internal/config"
)

// Publisher is the narrow post-promotion hook the ACME manager needs.
type Publisher interface {
	Publish(context.Context, *config.Certificate, []byte, []byte) error
}

// DefaultPublisher writes configured certificate exports.
type DefaultPublisher struct{}

func (DefaultPublisher) Publish(ctx context.Context, cert *config.Certificate, fullchain, key []byte) error {
	return Export(ctx, cert.Export, cert.Name, fullchain, key)
}

// Export writes fullchain.pem and privkey.pem beneath a certificate-specific
// directory, locally and/or through the existing hardened remote transports.
func Export(ctx context.Context, cfg *config.CertificateExport, cert string, fullchain, key []byte) error {
	if cfg == nil {
		return nil
	}
	// ".." passes filepath.Base unchanged, so the equality test alone let it through: the export
	// landed one directory above LocalDir, outside the tree the operator configured. The guard is
	// the only one on this path -- the config layer does not restrict the characters a certificate
	// name may contain -- so the check is explicit about the two names that navigate rather than
	// name, and about the separator.
	if cert == "" || cert == "." || cert == ".." || filepath.Base(cert) != cert ||
		strings.ContainsRune(cert, os.PathSeparator) {
		return fmt.Errorf("unsafe certificate export name %q", cert)
	}
	dir, err := os.MkdirTemp("", ".wecert-export-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	files := map[string][]byte{"fullchain.pem": fullchain, "privkey.pem": key}
	for name, data := range files {
		if err := writeAtomic(filepath.Join(dir, name), data); err != nil {
			return err
		}
	}
	if cfg.LocalDir != "" {
		out := filepath.Join(cfg.LocalDir, cert)
		if err := os.MkdirAll(out, 0o700); err != nil {
			return fmt.Errorf("create certificate export directory: %w", err)
		}
		for name, data := range files {
			if err := writeAtomic(filepath.Join(out, name), data); err != nil {
				return err
			}
		}
	}
	for _, target := range cfg.RemoteTargets {
		// Export carries private keys: when hmacKeyFile is configured it must load
		// or the export fails. Publishing unsigned material while the operator
		// believes the bucket is signed is the same lie the snapshot path refuses.
		hmacKey, err := backup.LoadHMACKey(target.HMACKeyFile)
		if err != nil {
			return fmt.Errorf("export %s to remote target %s: %w", cert, target.Name, err)
		}
		for name := range files {
			t := backup.Target{HMACKey: hmacKey, Type: target.Type, Name: target.Name, Bucket: target.Bucket, Prefix: filepath.ToSlash(filepath.Join(target.Prefix, cert)), Endpoint: target.Endpoint, Region: target.Region, Host: target.Host, Username: target.Username, RemoteDir: filepath.ToSlash(filepath.Join(target.RemoteDir, cert)), PasswordEnv: target.PasswordEnv, PrivateKeyFile: target.PrivateKeyFile, PrivateKeyPassphraseEnv: target.PrivateKeyPassphraseEnv, KnownHostsFile: target.KnownHostsFile, SecretIDEnv: target.SecretIDEnv, SecretKeyEnv: target.SecretKeyEnv, Timeout: target.TimeoutDur}
			if err := backup.Upload(ctx, t, filepath.Join(dir, name)); err != nil {
				return fmt.Errorf("export %s to remote target %s: %w", cert, target.Name, err)
			}
		}
	}
	return nil
}

func writeAtomic(dst string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".wecert-export-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// fsync before rename: this writes privkey.pem. Without it a crash can leave the
	// name in place and the bytes empty -- a deployment that then loads the key is
	// worse off than one with no export at all.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, dst); err != nil {
		return err
	}
	ok = true
	return nil
}
