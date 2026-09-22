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
		if d.nothingBoundYet(ctx, client, oldID, newID) {
			d.log.Warn("neither the old nor the new certificate is bound to anything yet; "+
				"recording the new one as uploaded and waiting for the one-time manual bind",
				"oldCertId", oldID, "newCertId", newID)
			return newID, ErrNothingBoundYet
		}
		if n, nerr := d.bindingsWith(ctx, client, newID, false); nerr == nil && n.count > 0 {
			if oldBindings, oerr := d.bindingsWith(ctx, client, oldID, false); oerr == nil && oldBindings.complete && oldBindings.count == 0 {
				d.log.Warn("the one-click update reported nothing to switch, but the new certificate is bound "+
					"and the old one is not; treating the switch as done (the rebind succeeded without being recorded)",
					"oldCertId", oldID, "newCertId", newID, "boundResources", n.count)
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
