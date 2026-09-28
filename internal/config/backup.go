package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Snapshot defaults. Defined here rather than in internal/state because this is the lower
// layer: the store takes the policy as arguments, the config decides it.
const (
	DefaultBackupInterval = 24 * time.Hour
	DefaultBackupKeep     = 7
)

// StateBackup controls the periodic consistent snapshot of state.db.
//
// Why it exists: losing state.db is the one documented disaster in this system -- the ACME
// account key (accounts are limited to 10 per IP per 3 hours), every in-flight order URL
// and every ARI certID live in it. Losing an order URL does not just cost an issuance: the
// replacement order counts against "5 certificates per exact set of identifiers / 7 days",
// a limit with no override. Until now the only guidance was a line in the README saying it
// is "the one thing to back up", with nothing implementing or checking it.
//
// On by default where it can be useful, off where it cannot: see normalize.
type StateBackup struct {
	// Enabled defaults to true when the state directory is writable, false otherwise.
	Enabled *bool `yaml:"enabled"`

	// Interval between snapshots. Default 24h; the minimum is 1 minute.
	Interval string `yaml:"interval"`

	// Keep is how many snapshots to retain, newest first. Default 7.
	Keep int `yaml:"keep"`

	// Dir is where snapshots are written. Empty means the directory holding state.db,
	// which is already 0700 and on the same filesystem (so SQLite's write and the rename
	// are cheap and atomic).
	Dir string `yaml:"dir"`

	// LocalDirs are additional local snapshot destinations, for example another
	// physical disk or a separately mounted backup volume. Each receives a
	// SQLite-consistent snapshot; state.db itself is never copied.
	LocalDirs []string `yaml:"localDirs"`

	// RemoteTargets deliver the consistent local snapshot to S3-compatible
	// storage (including COS) or SFTP. Credentials are deliberately references,
	// never YAML values.
	RemoteTargets []BackupTarget `yaml:"remoteTargets"`

	// AllowUnencryptedRemote is the explicit decision to upload snapshots whose
	// private keys are in the clear. Required whenever RemoteTargets is non-empty
	// and stateEncryption.keyFile is unset: without it the daemon refuses to start
	// (and -dry-run refuses to pass), because the install path must not be able to
	// copy the ACME account key and every certificate private key into a bucket
	// without someone choosing that. The key file is the other way out and is
	// preferred. Also accepted as wecert -accept-plaintext-backups, for
	// automation that cannot edit the config.
	AllowUnencryptedRemote bool `yaml:"allowUnencryptedRemote,omitempty"`

	// Parsed, filled in by normalize.
	IntervalDur time.Duration `yaml:"-"`
}

// EnabledOr returns the snapshot switch, or def when it is unset.
func (b *StateBackup) EnabledOr(def bool) bool {
	if b.Enabled == nil {
		return def
	}
	return *b.Enabled
}

func (b *StateBackup) normalize() error {
	var err error
	if b.IntervalDur, err = parseDuration(b.Interval, DefaultBackupInterval, "stateBackup.interval"); err != nil {
		return err
	}
	// A snapshot per pass would be pointless churn; a snapshot per hour is the useful
	// floor. The bound also keeps a typo like "1s" from filling the disk.
	if b.IntervalDur < time.Minute {
		return fmt.Errorf("stateBackup.interval is %s, which is below the 1m minimum: "+
			"snapshots are a recovery mechanism, not a change log, and a very short interval just "+
			"fills the disk with near-identical copies", b.IntervalDur)
	}
	if b.Keep == 0 {
		b.Keep = DefaultBackupKeep
	}
	if b.Keep < 1 {
		return fmt.Errorf("stateBackup.keep must be at least 1, got %d "+
			"(0 means \"use the default\"; there is no way to disable retention without disabling backups)", b.Keep)
	}
	if b.Keep > 365 {
		return fmt.Errorf("stateBackup.keep is %d, which would retain more than a year of snapshots "+
			"of a file holding private keys; keep at most 365", b.Keep)
	}
	seen := map[string]bool{}
	if b.Dir != "" {
		seen[filepath.Clean(b.Dir)] = true
	}
	for i, dir := range b.LocalDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return fmt.Errorf("stateBackup.localDirs[%d] is empty", i)
		}
		clean := filepath.Clean(dir)
		if seen[clean] {
			return fmt.Errorf("stateBackup.localDirs[%d] duplicates another snapshot destination %q", i, clean)
		}
		seen[clean] = true
		b.LocalDirs[i] = clean
	}
	for i := range b.RemoteTargets {
		if err := b.RemoteTargets[i].normalize(i); err != nil {
			return err
		}
	}
	return nil
}

// BackupTarget is one off-host snapshot destination.
type BackupTarget struct {
	// HMACKeyFile holds a key used to sign uploaded snapshots (HMAC-SHA256 sidecar).
	// Without it a writable backup bucket is a trusted restore source. Prefer a
	// file over an inline value; the key is NOT the stateEncryption master.
	HMACKeyFile             string `yaml:"hmacKeyFile,omitempty"`
	Type                    string `yaml:"type"` // s3, cos, or sftp
	Name                    string `yaml:"name"`
	Bucket                  string `yaml:"bucket"`
	Prefix                  string `yaml:"prefix"`
	Endpoint                string `yaml:"endpoint"`
	Region                  string `yaml:"region"`
	Host                    string `yaml:"host"`
	Username                string `yaml:"username"`
	RemoteDir               string `yaml:"remoteDir"`
	PasswordEnv             string `yaml:"passwordEnv"`
	PrivateKeyFile          string `yaml:"privateKeyFile"`
	PrivateKeyPassphraseEnv string `yaml:"privateKeyPassphraseEnv"`
	KnownHostsFile          string `yaml:"knownHostsFile"`
	// SecretIDEnv / SecretKeyEnv are COS credential environment-variable names.
	// They default to TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY for COS
	// and are ignored by AWS S3, which keeps using its standard credential chain.
	SecretIDEnv  string        `yaml:"secretIdEnv"`
	SecretKeyEnv string        `yaml:"secretKeyEnv"`
	Keep         int           `yaml:"keep"`
	Timeout      string        `yaml:"timeout"`
	TimeoutDur   time.Duration `yaml:"-"`
}

func (t *BackupTarget) normalize(i int) error {
	t.Type = strings.ToLower(strings.TrimSpace(t.Type))
	t.Name = strings.TrimSpace(t.Name)
	switch t.Type {
	case "s3", "cos":
		if t.Bucket == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d].bucket is required for %s", i, t.Type)
		}
		if t.Type == "cos" && strings.TrimSpace(t.Endpoint) == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d].endpoint is required for cos", i)
		}
		if t.Type == "cos" {
			if t.SecretIDEnv == "" {
				t.SecretIDEnv = "TENCENTCLOUD_SECRET_ID"
			}
			if t.SecretKeyEnv == "" {
				t.SecretKeyEnv = "TENCENTCLOUD_SECRET_KEY"
			}
		}
	case "sftp":
		if t.Host == "" || t.Username == "" || t.RemoteDir == "" || t.KnownHostsFile == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d] sftp requires host, username, remoteDir and knownHostsFile", i)
		}
		if t.PrivateKeyFile == "" && t.PasswordEnv == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d] sftp requires privateKeyFile or passwordEnv", i)
		}
	default:
		return fmt.Errorf("stateBackup.remoteTargets[%d].type must be s3, cos or sftp, got %q", i, t.Type)
	}
	if t.Name == "" {
		t.Name = fmt.Sprintf("%s-%d", t.Type, i+1)
	}
	if t.Keep == 0 {
		t.Keep = DefaultBackupKeep
	}
	if t.Keep < 1 {
		return fmt.Errorf("stateBackup.remoteTargets[%d].keep must be at least 1", i)
	}
	var err error
	if t.TimeoutDur, err = parseDuration(t.Timeout, 5*time.Minute, fmt.Sprintf("stateBackup.remoteTargets[%d].timeout", i)); err != nil {
		return err
	}
	return nil
}

// normalizeList trims, lowercases, rejects empties and removes duplicates, preserving order.
func normalizeList(field string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return nil, fmt.Errorf("%s contains an empty entry; every entry must name a value "+
				"(a blank one would be sent to the cloud API as-is)", field)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}
