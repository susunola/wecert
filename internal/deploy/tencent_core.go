package deploy

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
)

type TencentCLB struct {
	credential CredentialFunc
	regions    []string
	types      []string
	log        *slog.Logger
	now        func() time.Time
	// enumerationBudget overrides defaultEnumerationBudget when non-zero. Tests set it to
	// keep the polling loop short in real time; production uses the default.
	enumerationBudget time.Duration
}

func (d *TencentCLB) enumerationWait() time.Duration {
	if d.enumerationBudget > 0 {
		return d.enumerationBudget
	}
	return defaultEnumerationBudget
}

type LazyTencentCLB struct {
	cfg config.Tencent
	log *slog.Logger

	mu    sync.Mutex
	inner *TencentCLB
}

func NewLazyTencentCLB(cfg config.Tencent, log *slog.Logger) *LazyTencentCLB {
	return &LazyTencentCLB{cfg: cfg, log: log}
}

func (d *LazyTencentCLB) client() (*TencentCLB, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inner != nil {
		return d.inner, nil
	}
	inner, err := NewTencentCLB(d.cfg, d.log)
	if err != nil {
		return nil, err
	}
	d.inner = inner
	return inner, nil
}

func (d *LazyTencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	inner, err := d.client()
	if err != nil {
		return "", err
	}
	return inner.Deploy(ctx, certName, oldID, certPEM, keyPEM)
}

func (d *LazyTencentCLB) Delete(ctx context.Context, certID string) error {
	if certID == "" {
		return nil
	}
	inner, err := d.client()
	if err != nil {
		return err
	}
	return inner.Delete(ctx, certID)
}

func NewTencentCLB(cfg config.Tencent, log *slog.Logger) (*TencentCLB, error) {
	src, err := NewCredentialSource(cfg)
	if err != nil {
		return nil, err
	}
	return &TencentCLB{
		credential: src,
		regions:    cfg.Regions,
		types:      cfg.ResourceTypes,
		log:        log,
		now:        time.Now,
	}, nil
}

const deployRecordGrace = 15 * time.Second

const defaultEnumerationBudget = 3 * time.Minute

type sslAPI interface {
	UploadCertificateWithContext(ctx context.Context, req *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
	UpdateCertificateInstanceWithContext(ctx context.Context, req *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error)
	DescribeHostUpdateRecordDetailWithContext(ctx context.Context, req *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error)
	DeleteCertificateWithContext(ctx context.Context, req *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error)
	DescribeDeleteCertificatesTaskResultWithContext(ctx context.Context, req *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error)
	CreateCertificateBindResourceSyncTaskWithContext(ctx context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error)
	DescribeCertificateBindResourceTaskResultWithContext(ctx context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error)
}

var newSSLClient = func(cred common.CredentialIface) (sslAPI, error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 60
	return ssl.NewClient(cred, "", cpf)
}

func (d *TencentCLB) client(ctx context.Context) (sslAPI, error) {
	cred, err := d.credential(ctx)
	if err != nil {
		return nil, err
	}
	return newSSLClient(cred)
}

var waitBetweenPolls = func(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
