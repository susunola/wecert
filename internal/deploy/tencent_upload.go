package deploy

import (
	"context"
	"errors"
	"fmt"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func (d *TencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	newID, err := d.Upload(ctx, certName, certPEM, keyPEM)
	if err != nil {
		return "", err
	}
	return d.DeployUploaded(ctx, certName, oldID, newID)
}

func sdkCallError(ctx context.Context, what string, err error) error {
	if cerr := ctx.Err(); errors.Is(cerr, context.Canceled) {
		return fmt.Errorf("%s: %w", what, cerr)
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%s: %w (context: %w)", what, err, cerr)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func (d *TencentCLB) Upload(ctx context.Context, certName string, certPEM, keyPEM []byte) (string, error) {
	client, err := d.client(ctx)
	if err != nil {
		return "", err
	}
	return d.upload(ctx, client, certName, certPEM, keyPEM)
}

func (d *TencentCLB) DeployUploaded(ctx context.Context, certName, oldID, newID string) (string, error) {
	client, err := d.client(ctx)
	if err != nil {
		return newID, err
	}
	return d.deployUploaded(ctx, client, certName, oldID, newID)
}

func (d *TencentCLB) deployUploaded(ctx context.Context, client sslAPI, certName, oldID, newID string) (string, error) {
	if oldID == "" {
		return newID, nil
	}
	if err := d.updateInstance(ctx, client, oldID, newID); err != nil {
		// The new certificate is enumerated ONCE and the answer is shared by both verdicts
		// below. Each verdict additionally needs the old certificate, so that one is
		// enumerated once as well, lazily, only on a path that reads it. The previous shape
		// (the pending-first-bind check enumerating the new certificate, then the repair path
		// enumerating it again) spent up to three uncached full enumerations -- each a
		// CreateCertificateBindResourceSyncTask plus up to enumerationWait of polling -- on
		// a single failed switch.
		//
		// Both verdicts must be built from COMPLETE answers where a zero is load-bearing: a
		// partial enumeration reports 0 for a certificate that is bound in a region the read
		// could not reach, and treating that as "nothing is bound" is how a needed switch
		// gets skipped and a listener keeps serving a certificate that is about to expire.
		// A non-zero count needs no such guard: it proves a binding no matter which regions
		// went unanswered (see bindingCount).
		// cached=false on both: these decide whether a switch took effect, and the SDK's
		// cache can answer from a completed task up to half an hour old.
		newBindings, nerr := d.bindingsWith(ctx, client, newID, false)
		if nerr == nil && newBindings.complete && newBindings.count == 0 {
			// Nothing is bound to either certificate: this is not a failed switch, it is the
			// documented first-issuance state, reached on a renewal because the first upload was
			// never bound by hand.
			//
			// The distinction matters because the two look identical to the cloud
			// (FailedOperation.CertificateDeployInstanceEmpty) and call for opposite answers.
			// Before this, every renewal of a certificate nobody had bound yet failed the pass,
			// so the promotion never ran and st.NotAfter/CertPEM stayed on the certificate that
			// was expiring: the state kept naming a certificate whose only remaining future was
			// to expire, and each failed cycle issued and uploaded another one.
			oldBindings, oerr := d.bindingsWith(ctx, client, oldID, false)
			if oerr == nil && oldBindings.complete && oldBindings.count == 0 {
				d.log.Warn("neither the old nor the new certificate is bound to anything yet; "+
					"recording the new one as uploaded and waiting for the one-time manual bind",
					"oldCertId", oldID, "newCertId", newID)
				return newID, ErrNothingBoundYet
			}
		} else if nerr == nil && newBindings.count > 0 {
			// Repair the historical wedge only when the old anchor is entirely gone. A
			// non-zero new binding alone is not completion: a partially failed task has
			// exactly that shape and must remain an error.
			//
			// Why the old anchor has to be checked: this path exists for a switch that happened
			// but was not recorded. The shape is that the rebind went through (or an earlier
			// attempt's did), so the OLD certificate has no bindings left and every later round
			// fails the "nothing to switch" check no matter how many certificates we upload.
			// Asking only about the new certificate would also accept a partial failure -- some
			// listeners switched, so n > 0 -- and then the state anchors on the new ID while the
			// rest stay on the old certificate, never to be revisited. Requiring oldBindings == 0
			// distinguishes the two structurally, without having to classify the error.
			// oldBindings == 0 is the load-bearing half, so it must come from a COMPLETE answer.
			// A partial enumeration that skipped a failed region also produces 0, and reading that
			// as "the old certificate is bound nowhere" is exactly how a half-finished switch gets
			// recorded as done -- with some listeners still serving the old certificate and nothing
			// left to revisit them.
			oldBindings, oerr := d.bindingsWith(ctx, client, oldID, false)
			if oerr == nil && oldBindings.complete && oldBindings.count == 0 {
				d.log.Warn("the one-click update reported nothing to switch, but the new certificate is bound "+
					"and the old one is not; treating the switch as done (the rebind succeeded without being recorded)",
					"oldCertId", oldID, "newCertId", newID, "boundResources", newBindings.count)
				return newID, nil
			}
		}
		return newID, err
	}
	return newID, nil
}

func (d *TencentCLB) ResumeDeploy(ctx context.Context, certName, oldID, uploadedID string) (string, error) {
	return d.DeployUploaded(ctx, certName, oldID, uploadedID)
}

func (d *LazyTencentCLB) ResumeDeploy(ctx context.Context, certName, oldID, uploadedID string) (string, error) {
	inner, err := d.client()
	if err != nil {
		return uploadedID, err
	}
	return inner.ResumeDeploy(ctx, certName, oldID, uploadedID)
}

func (d *LazyTencentCLB) Upload(ctx context.Context, certName string, certPEM, keyPEM []byte) (string, error) {
	inner, err := d.client()
	if err != nil {
		return "", err
	}
	return inner.Upload(ctx, certName, certPEM, keyPEM)
}

func (d *LazyTencentCLB) DeployUploaded(ctx context.Context, certName, oldID, uploadedID string) (string, error) {
	inner, err := d.client()
	if err != nil {
		return uploadedID, err
	}
	return inner.DeployUploaded(ctx, certName, oldID, uploadedID)
}

func (d *TencentCLB) upload(ctx context.Context, client sslAPI, certName string, certPEM, keyPEM []byte) (string, error) {
	req := ssl.NewUploadCertificateRequest()
	req.CertificatePublicKey = common.StringPtr(string(certPEM))
	req.CertificatePrivateKey = common.StringPtr(string(keyPEM))
	req.CertificateType = common.StringPtr("SVR")
	req.Alias = common.StringPtr("wecert/" + certName)
	req.Repeatable = common.BoolPtr(true)

	resp, err := client.UploadCertificateWithContext(ctx, req)
	if err != nil {
		return "", sdkCallError(ctx, "UploadCertificate", err)
	}
	if resp.Response == nil {
		return "", errors.New("UploadCertificate returned an empty response")
	}
	if id := derefStr(resp.Response.CertificateId); id != "" {
		return id, nil
	}
	if dup := derefStr(resp.Response.RepeatCertId); dup != "" {
		return dup, nil
	}
	return "", errors.New("UploadCertificate returned neither a CertificateId nor a RepeatCertId; the certificate was not stored")
}
