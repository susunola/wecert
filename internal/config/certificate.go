package config

import (
	"time"
)

// Certificate is the desired state of one certificate.
type Certificate struct {
	Name        string   `yaml:"name" json:"name"`
	Domains     []string `yaml:"domains" json:"domains"`
	Profile     string   `yaml:"profile" json:"profile"`
	KeyType     string   `yaml:"keyType" json:"keyType"`
	RenewBefore string   `yaml:"renewBefore,omitempty" json:"renewBefore,omitempty"`
	Deploy      Deploy   `yaml:"deploy" json:"deploy"`
	// FailureFallback overrides the global failureFallback policy for this
	// certificate only. A non-nil block with enabled: false explicitly opts this
	// certificate out while other certificates may still degrade near expiry.
	FailureFallback *FailureFallback `yaml:"failureFallback,omitempty" json:"failureFallback,omitempty"`
	// Export writes the issued full chain and private key to operator-selected
	// local and/or remote destinations after a successful promotion.
	Export *CertificateExport `yaml:"export,omitempty" json:"export,omitempty"`
	// UIN tags this certificate with a Tencent Cloud account. Empty means inherit
	// tencent.uin. The inventory uses it only for display and grouping; it does
	// not change which credentials deploy the certificate.
	UIN string `yaml:"uin,omitempty" json:"uin,omitempty"`

	// Parsed durations, filled in by normalize.
	RenewBeforeDur time.Duration `yaml:"-" json:"-"`
}

// CertificateExport is an opt-in private-key distribution target. RemoteTargets
// use the same credential-reference-only shape as state backups.
type CertificateExport struct {
	LocalDir      string         `yaml:"localDir,omitempty" json:"localDir,omitempty"`
	RemoteTargets []BackupTarget `yaml:"remoteTargets,omitempty" json:"remoteTargets,omitempty"`
}

// Deploy describes where the issued certificate should be deployed.
//
// On Tencent Cloud, first issuance only uploads: there is no binding on that side
// yet, so a human binds once in the console and later renewals are swapped by
// UpdateCertificateInstance. On nginx there is no console step -- writing the
// files and reloading *is* the bind.
type Deploy struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Target overrides DeploySettings.Target for this certificate only.
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
	// Nginx is read only when this certificate's target is nginx.
	Nginx *NginxCert `yaml:"nginx,omitempty" json:"nginx,omitempty"`
}
