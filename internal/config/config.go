// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"time"
)

// ACME profile names. The Max Names cap varies by profile.
const (
	ProfileClassic    = "classic"
	ProfileTLSServer  = "tlsserver"
	ProfileShortLived = "shortlived"
)

// Let's Encrypt directory URLs.
const (
	DirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	DirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

const (
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
	KeyTypeRSA2048   = "rsa2048"
	KeyTypeRSA4096   = "rsa4096"
)

const (
	CredentialStatic  = "static"
	CredentialCVMRole = "cvm-role"
)

// profileMaxNames is the maximum identifier count each profile allows.
// classic allows 100, but the newer tlsserver / shortlived only 25 — reject
// locally rather than send an order the CA will refuse and burn quota on.
var profileMaxNames = map[string]int{
	ProfileClassic:    100,
	ProfileTLSServer:  25,
	ProfileShortLived: 25,
}

// profileRenewBefore is each profile's default renew-ahead duration.
// A fallback only when ARI is unavailable; otherwise suggestedWindow wins.
var profileRenewBefore = map[string]time.Duration{
	ProfileClassic:    30 * 24 * time.Hour,
	ProfileTLSServer:  15 * 24 * time.Hour,
	ProfileShortLived: 48 * time.Hour,
}

type Config struct {
	StatePath       string          `yaml:"statePath"`
	StateBackup     StateBackup     `yaml:"stateBackup"`
	StateEncryption StateEncryption `yaml:"stateEncryption"`
	ACME            ACME            `yaml:"acme"`
	DNS             DNS             `yaml:"dns"`
	Tencent         Tencent         `yaml:"tencent"`
	// Deploy picks where issued certificates go: the Tencent Cloud CLB path (default,
	// the shape this program was built for) or a local nginx directory + reload.
	Deploy       DeploySettings  `yaml:"deploy"`
	Nginx        NginxTarget     `yaml:"nginx"`
	Metrics      Metrics         `yaml:"metrics"`
	Webhook      Webhook         `yaml:"webhook"`
	DesiredState DesiredState    `yaml:"desiredState"`
	Onboarding   Onboarding      `yaml:"onboarding"`
	Probe        Probe           `yaml:"probe"`
	Fallback     FailureFallback `yaml:"failureFallback"`
	Certificates []Certificate   `yaml:"certificates"`
}

// StateEncryption protects private material stored in state.db. KeyFile is
// environment-expanded, so systemd LoadCredential can supply it without YAML.
type StateEncryption struct {
	KeyFile string `yaml:"keyFile,omitempty"`
	Key     string `yaml:"-"`
}

// Deploy target names for DeploySettings.Target and Certificate.Deploy.Target.
const (
	DeployTargetTencent = "tencent"
	DeployTargetNginx   = "nginx"
)

// DeploySettings is the process-wide deploy backend choice.
//
// Per-certificate deploy.enabled still decides whether anything is pushed at all;
// this field only says *where* a pushed certificate lands. Keeping the two apart
// is what lets a fleet mix "local state only", "CLB" and "nginx" certificates in
// one config without inventing a third flag that means "enabled but where?".
type DeploySettings struct {
	// Target is DeployTargetTencent (default) or DeployTargetNginx.
	Target string `yaml:"target,omitempty"`
}

// NginxTarget describes the local nginx certificate directory layout and the
// command that makes nginx pick up a new file set.
//
// This is for the deployment where TLS does **not** terminate at a cloud LB:
// wecert writes fullchain.pem + privkey.pem on disk and reloads nginx. There is
// no cloud certificate id and no console bind -- the "binding" is the pair of
// files nginx's config already points at.
type NginxTarget struct {
	// DirTemplate is the directory per certificate. "%s" is replaced with the
	// certificate name. Default: /etc/nginx/ssl/%s
	//
	// A template rather than one shared directory: nginx server blocks usually
	// name their ssl_certificate paths, and one directory per certificate keeps
	// a name's key out of every other certificate's directory.
	DirTemplate string `yaml:"dirTemplate,omitempty"`

	// CertFile is the leaf+chain file name inside the directory. Default fullchain.pem.
	// nginx's ssl_certificate should point at this file.
	CertFile string `yaml:"certFile,omitempty"`

	// KeyFile is the private key file name inside the directory. Default privkey.pem.
	// Written 0600: the key is the credential that makes the certificate worth anything.
	KeyFile string `yaml:"keyFile,omitempty"`

	// Reload is the command run after the files land. Default: systemctl reload nginx.
	//
	// An argv slice, not a shell string: quoting rules and PATH lookups are exactly
	// how a deploy path becomes a root command-injection story. Empty means "write
	// the files and do not reload", which is only honest for an operator who reloads
	// on a schedule and knows it.
	Reload []string `yaml:"reload,omitempty"`
}

// NginxCert lets one certificate override the directory only. File names and the
// reload command stay global -- a fleet that needs two reload commands is two
// processes, not one config fighting itself.
type NginxCert struct {
	Dir string `yaml:"dir,omitempty"`
}

// ProfileMaxNames returns the identifier cap a profile allows, or 0 for an unknown profile.
//
// Exported because onboarding has to cap a group by the profile the group will actually be issued
// with, not by a configured default: splitting by the default alone let a tlsserver group exceed
// 25 identifiers, and the document was then rejected at write time on every round.
func ProfileMaxNames(profile string) int {
	if n, ok := profileMaxNames[profile]; ok {
		return n
	}
	return 0
}

// MaxNames returns the maximum domain count allowed by this certificate's
// profile.
func (c *Certificate) MaxNames() int { return ProfileMaxNames(c.Profile) }

// ProfileRenewBefore returns the profile's default renew-ahead duration, or 0 for an
// unknown profile.
//
// Exported for the same reason as ProfileMaxNames: spec.Revision fingerprints the
// EFFECTIVE renewBefore, and a certificate that never went through
// NormalizeCertificates (onboarding hashes its freshly built list before WriteDocument
// validates it) carries neither the parsed duration nor the default.
func ProfileRenewBefore(profile string) time.Duration { return profileRenewBefore[profile] }

// maxConfigBytes bounds a config read, the same way maxDocumentBytes bounds a desired-state
// document in internal/spec. A hand-written config is tiny -- a fleet of thousands of
// certificates fits in a fraction of this -- so a file past the cap is a mistake or a
// mounted surprise, and is refused rather than parsed.
const maxConfigBytes = 16 << 20

// Load reads and validates the configuration file.
var profileValidity = map[string]time.Duration{
	ProfileClassic:    90 * 24 * time.Hour,
	ProfileTLSServer:  45 * 24 * time.Hour,
	ProfileShortLived: 160 * time.Hour,
}
