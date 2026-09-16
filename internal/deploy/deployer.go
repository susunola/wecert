// Package deploy pushes issued certificates to the systems that actually consume them.
//
// This project is shaped as "TLS terminates on Tencent Cloud CLB", so there is no agent
// on any node and no certificate file distribution -- the whole deploy action is a
// handful of Tencent Cloud API calls.
package deploy

import "context"

// Deployer abstracts the deployment target.
//
// It is an interface because Tencent Cloud offers two routes and the controller should
// not care which one is in use.
//
//   - UpdateCertificateInstance (public, this project's default):
//     upload the new certificate to get a new CertId, then let Tencent Cloud itself
//     discover which CLB listeners are bound to the old certificate and swap them over.
//     The win is that we never maintain a listener inventory, and multiple SNI
//     certificates on one listener cannot be overwritten by mistake.
//
//   - UploadUpdateCertificateInstance (needs a support ticket to whitelist):
//     the certificate ID stays the same and the content is replaced in place; the only
//     deployment target supported is clb.
//     Its sole extra benefit is skipping one CertId change -- a nice-to-have.
type Deployer interface {
	// Deploy pushes the new certificate and returns the certificate identifier that
	// should be recorded afterwards.
	// An empty oldID means first issuance (no binding exists on the Tencent Cloud side).
	Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (newID string, err error)

	// Delete removes a retired certificate, keeping the Tencent Cloud certificate count
	// from growing without bound.
	Delete(ctx context.Context, certID string) error

	// Bindings returns how many cloud resources this certificate is currently bound to.
	//
	// Read-only. It exists because the first issuance only uploads and does not bind, so
	// DeployConfirmed is false; after a human binds it in the console someone has to come
	// back and confirm, otherwise the deployed metric reports "not deployed" for the
	// certificate's entire lifetime.
	//
	// Finding no binding does not mean failure -- returning 0 is fine. Callers use that to
	// tell "not bound yet" apart from "cannot query".
	Bindings(ctx context.Context, certID string) (int, error)
}

// Noop is used when deploy.enabled=false: certificates stay only in the local state db.
type Noop struct{}

// Deploy returns oldID unchanged and performs no remote operation.
func (Noop) Deploy(_ context.Context, _ string, oldID string, _, _ []byte) (string, error) {
	return oldID, nil
}

// Delete does nothing.
func (Noop) Delete(_ context.Context, _ string) error { return nil }

// Bindings is always 0: Noop deploys nowhere, so there is nothing to bind.
func (Noop) Bindings(_ context.Context, _ string) (int, error) { return 0, nil }
