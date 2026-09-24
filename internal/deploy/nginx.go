package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/atomicfile"
	"github.com/susunola/wecert/internal/config"
)

// Nginx writes certificates to a local directory and reloads nginx.
//
// The CLB path exists because TLS terminates at a cloud load balancer and the
// fleet has no node agent. The opposite shape -- nginx on the same box as the
// renewal process -- needs no cloud certificate id at all: the deploy action is
// "write fullchain.pem + privkey.pem atomically, then reload". That also means:
//
//   - the id this deployer returns is the directory (stable, name-derived), not a
//     remote resource id;
//   - Delete is "remove those two files", not "reclaim a cloud certificate slot";
//   - Bindings is 1 when the files are present: there is no separate bind step,
//     so a successful write *is* a confirmed deployment (no console bind).
//
// Reload runs as whatever user wecert runs as (systemd unit: wecert). Reloading
// nginx usually wants root or CAP_KILL against the master; the shipped unit
// cannot do that. Operators either run a sudoers rule for exactly
// `systemctl reload nginx`, point reload at a helper script that is allowed to,
// or set reload: [] and reload on their own schedule.
type Nginx struct {
	dirTemplate string
	certFile    string
	keyFile     string
	reload      []string
	// overrides maps a certificate name to an explicit directory (deploy.nginx.dir).
	overrides map[string]string
	log       interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Error(msg string, args ...any)
	}
	// now is the clock for tests.
	now func() time.Time
}

// NginxOptions is the construction input; see config.NginxTarget for the fields.
type NginxOptions struct {
	DirTemplate string
	CertFile    string
	KeyFile     string
	Reload      []string
	// Overrides is certName -> directory, from Certificate.Deploy.Nginx.Dir.
	Overrides map[string]string
}

// NewNginx builds the local nginx deployer.
func NewNginx(opts NginxOptions, log interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}) (*Nginx, error) {
	if opts.DirTemplate == "" || !strings.Contains(opts.DirTemplate, "%s") {
		return nil, fmt.Errorf("nginx dirTemplate %q must contain %%s", opts.DirTemplate)
	}
	if opts.CertFile == "" || opts.KeyFile == "" || opts.CertFile == opts.KeyFile {
		return nil, fmt.Errorf("nginx certFile and keyFile must be set and distinct (got %q and %q)",
			opts.CertFile, opts.KeyFile)
	}
	for i := range opts.Reload {
		if strings.TrimSpace(opts.Reload[i]) == "" {
			return nil, fmt.Errorf("nginx reload[%d] is empty", i)
		}
	}
	return &Nginx{
		dirTemplate: opts.DirTemplate,
		certFile:    opts.CertFile,
		keyFile:     opts.KeyFile,
		reload:      opts.Reload,
		overrides:   opts.Overrides,
		log:         log,
		now:         time.Now,
	}, nil
}

// NewNginxFromConfig is the config-shaped constructor used by cmd/wecert.
func NewNginxFromConfig(cfg config.Config, log interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}) (*Nginx, error) {
	overrides := map[string]string{}
	for _, c := range cfg.Certificates {
		if c.Deploy.Nginx != nil && c.Deploy.Nginx.Dir != "" {
			overrides[c.Name] = c.Deploy.Nginx.Dir
		}
	}
	return NewNginx(NginxOptions{
		DirTemplate: cfg.Nginx.DirTemplate,
		CertFile:    cfg.Nginx.CertFile,
		KeyFile:     cfg.Nginx.KeyFile,
		Reload:      cfg.Nginx.Reload,
		Overrides:   overrides,
	}, log)
}

// dirFor resolves the certificate directory. "%s" is the certificate name -- not
// the first domain, which is a free-form user string with wildcards in it.
func (n *Nginx) dirFor(certName string) string {
	if d, ok := n.overrides[certName]; ok && d != "" {
		return d
	}
	return strings.ReplaceAll(n.dirTemplate, "%s", certName)
}

// nginxID is the stable "cloud id" for this deployer: callers persist whatever
// Deploy returns as DeployedCertID / DeploymentCertID. A path is the identity
// because there is no remote resource to name.
func nginxID(dir string) string { return "nginx:" + dir }

// dirFromID reverses nginxID for Delete.
func dirFromID(id string) (string, bool) {
	dir, ok := strings.CutPrefix(id, "nginx:")
	return dir, ok && dir != ""
}

// Deploy writes fullchain + key and reloads nginx. Prefer the staged pair
// (Upload + DeployUploaded) when available: that is what lets the caller persist
// the directory before the reload, so a crash between the two leaves files on
// disk that the next pass can name. Deploy keeps the same total effect for
// callers that only know the one-shot interface.
func (n *Nginx) Deploy(ctx context.Context, certName, _ string, certPEM, keyPEM []byte) (string, error) {
	id, err := n.Upload(ctx, certName, certPEM, keyPEM)
	if err != nil {
		return id, err
	}
	return n.DeployUploaded(ctx, certName, "", id)
}

// Upload writes the files and returns the directory identity. It does not reload.
func (n *Nginx) Upload(_ context.Context, certName string, certPEM, keyPEM []byte) (string, error) {
	dir := n.dirFor(certName)
	id := nginxID(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return id, fmt.Errorf("create nginx certificate directory %s: %w", dir, err)
	}
	// Chain is readable by the nginx worker (often not root); the key is not.
	// atomicfile.Write replaces via rename, so a reload that races the write sees
	// either the old pair or the new one -- never a half-written PEM.
	certPath := filepath.Join(dir, n.certFile)
	keyPath := filepath.Join(dir, n.keyFile)
	if err := atomicfile.Write(certPath, certPEM, 0o644); err != nil {
		return id, fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := atomicfile.Write(keyPath, keyPEM, 0o600); err != nil {
		return id, fmt.Errorf("write %s: %w", keyPath, err)
	}
	if n.log != nil {
		n.log.Info("nginx certificate files written",
			"cert", certName, "dir", dir, "certFile", n.certFile, "keyFile", n.keyFile)
	}
	return id, nil
}

// DeployUploaded reloads nginx after the files are already on disk (or are about
// to be trusted as on disk from an earlier Upload).
func (n *Nginx) DeployUploaded(ctx context.Context, certName, _, uploadedID string) (string, error) {
	dir := n.dirFor(certName)
	if d, ok := dirFromID(uploadedID); ok && d != "" {
		dir = d
	}
	id := nginxID(dir)
	if !n.filesPresent(dir) {
		// Reload without files would tell nginx to serve whatever is still in its
		// memory / the old pair -- success with no deploy. Say so.
		return id, fmt.Errorf("nginx: cannot deploy %s: %s/%s are missing under %s",
			certName, n.certFile, n.keyFile, dir)
	}
	if len(n.reload) == 0 {
		// Files are on disk but nothing told nginx. Claiming success here made
		// manager_done set DeployConfirmed, and the deployed metric said "serving
		// the new certificate" while nginx may still hold the old one in memory.
		// ErrSwitchUnverified is the existing "cloud says done, independent check
		// did not confirm" outcome -- same honesty, same handling.
		if n.log != nil {
			n.log.Warn("nginx reload command is empty; files are on disk but nginx has not been told",
				"cert", certName, "dir", dir)
		}
		return id, fmt.Errorf("%w: nginx reload is disabled (nginx.reload is empty), so nothing "+
			"confirmed the new files are being served", ErrSwitchUnverified)
	}
	if err := n.runReload(ctx, certName, dir); err != nil {
		return id, err
	}
	return id, nil
}

// ResumeDeploy is DeployUploaded under another name: the files are already on
// disk and only the reload is left (see RetryableDeployer).
func (n *Nginx) ResumeDeploy(ctx context.Context, certName, _ string, uploadedID string) (string, error) {
	return n.DeployUploaded(ctx, certName, "", uploadedID)
}

// Delete removes the certificate files. Safe on a non-existent directory: the
// reaper calls this for every retired id, including one another process already
// removed.
func (n *Nginx) Delete(_ context.Context, certID string) error {
	if certID == "" {
		return nil
	}
	dir, ok := dirFromID(certID)
	if !ok {
		// An id this deployer did not mint is not ours to remove. Claiming success
		// would make the reaper forget it while the real object stays.
		return fmt.Errorf("nginx: %w: %q", ErrDeploymentDisabled, certID)
	}
	var errs []error
	for _, name := range []string{n.keyFile, n.certFile} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
		}
	}
	if n.log != nil {
		n.log.Info("nginx certificate files removed", "certId", certID, "dir", dir)
	}
	return errors.Join(errs...)
}

// Bindings reports 1 when both files exist. There is no separate bind step:
// the pair of files nginx's config points at *is* the deployment.
//
// complete is always true: this is a local stat, not a multi-region enumeration.
func (n *Nginx) Bindings(_ context.Context, certID string) (int, bool, error) {
	if certID == "" {
		return 0, true, nil
	}
	dir, ok := dirFromID(certID)
	if !ok {
		return 0, true, nil
	}
	// reload: [] means the files are on disk but nothing told nginx. Reporting
	// Bindings=1 made confirmBinding set DeployConfirmed, and the deployed metric
	// claimed "serving the new certificate" while nginx may still hold the old one
	// in memory. Files present is NOT "being served" here.
	if len(n.reload) == 0 {
		return 0, true, nil
	}
	if n.filesPresent(dir) {
		return 1, true, nil
	}
	return 0, true, nil
}

func (n *Nginx) filesPresent(dir string) bool {
	cert := filepath.Join(dir, n.certFile)
	key := filepath.Join(dir, n.keyFile)
	cs, err := os.Stat(cert)
	if err != nil || cs.Size() == 0 {
		return false
	}
	ks, err := os.Stat(key)
	if err != nil || ks.Size() == 0 {
		return false
	}
	return true
}

// reloadTimeout bounds the reload command. nginx -s reload is normally instant;
// systemctl can block on a stuck unit. The certificate is already on disk at this
// point -- the timeout only stops one bad reload from holding the convergence
// loop (and the per-certificate claim) for the rest of the pass.
const reloadTimeout = 30 * time.Second

func (n *Nginx) runReload(ctx context.Context, certName, dir string) error {
	rctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()
	// exec.CommandContext, argv form, no shell: see NginxTarget.Reload.
	cmd := exec.CommandContext(rctx, n.reload[0], n.reload[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("nginx reload %v failed: %w: %s", n.reload, err, msg)
		}
		return fmt.Errorf("nginx reload %v failed: %w", n.reload, err)
	}
	if n.log != nil {
		n.log.Info("nginx reloaded", "cert", certName, "dir", dir, "cmd", n.reload)
	}
	return nil
}

// Options exposes the layout for tests and for the startup log line.
func (n *Nginx) Options() NginxOptions {
	return NginxOptions{
		DirTemplate: n.dirTemplate,
		CertFile:    n.certFile,
		KeyFile:     n.keyFile,
		Reload:      n.reload,
		Overrides:   n.Overrides(),
	}
}

func (n *Nginx) Overrides() map[string]string {
	out := make(map[string]string, len(n.overrides))
	for k, v := range n.overrides {
		out[k] = v
	}
	return out
}
