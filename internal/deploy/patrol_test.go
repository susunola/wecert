package deploy

import (
	"context"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
)

func patrolDeployer(t *testing.T, fake *fakeSSLAPI) *TencentCLB {
	t.Helper()
	stubSSLClient(t, fake)
	d, err := NewTencentCLB(config.Tencent{
		CredentialMode: config.CredentialStatic,
		SecretID:       "id", SecretKey: "key",
		Regions: []string{"ap-guangzhou"},
	}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func patrolTaskResult(taskID string, count uint64) func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
	return func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
		return &ssl.DescribeCertificateBindResourceTaskResultResponse{
			Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
				SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
					TaskId: common.StringPtr(taskID),
					Status: common.Uint64Ptr(bindStatusDone),
					BindResourceResult: []*ssl.BindResourceResult{{
						ResourceType: common.StringPtr("clb"),
						BindResourceRegionResult: []*ssl.BindResourceRegionResult{
							{Region: common.StringPtr("ap-guangzhou"), TotalCount: common.Uint64Ptr(count), Error: common.StringPtr("")},
						},
					}},
				}},
			},
		}, nil
	}
}

func patrolCreateTask(taskID, certID string) func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
	return func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
		return &ssl.CreateCertificateBindResourceSyncTaskResponse{
			Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{
				CertTaskIds: []*ssl.CertTaskId{{
					CertId: common.StringPtr(certID),
					TaskId: common.StringPtr(taskID),
				}},
			},
		}, nil
	}
}

// Confirmed when the state store's cert is bound; unmanaged when the account holds a
// cert wecert never named.
func TestPatrolClassifiesConfirmedAndUnmanaged(t *testing.T) {
	ForgetBindings("cert-live")
	ForgetBindings("cert-gone")

	fake := &fakeSSLAPI{
		listCertsFn: func(context.Context, *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
			return &ssl.DescribeCertificatesResponse{
				Response: &ssl.DescribeCertificatesResponseParams{
					TotalCount: common.Uint64Ptr(2),
					Certificates: []*ssl.Certificates{{
						CertificateId: common.StringPtr("cert-live"),
						Alias:         common.StringPtr("wecert/www"),
					}, {
						CertificateId: common.StringPtr("cert-console"),
						Alias:         common.StringPtr("console"),
					}},
				},
			}, nil
		},
		createTaskFn: func(_ context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			id := *req.CertificateIds[0]
			return patrolCreateTask("t-"+id, id)(context.Background(), req)
		},
		taskResultFn: func(_ context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			taskID := *req.TaskIds[0]
			if taskID == "t-cert-live" {
				return patrolTaskResult(taskID, 2)(nil, nil)
			}
			return patrolTaskResult(taskID, 0)(nil, nil)
		},
	}
	d := patrolDeployer(t, fake)
	findings, err := d.PatrolBindings(context.Background(), []KnownCert{
		{Name: "www", DeployedID: "cert-live"},
	})
	if err != nil {
		t.Fatalf("PatrolBindings: %v", err)
	}
	kinds := map[PatrolKind]int{}
	for _, f := range findings {
		kinds[f.Kind]++
	}
	if kinds[PatrolConfirmed] != 1 {
		t.Errorf("confirmed = %d, want 1; findings=%+v", kinds[PatrolConfirmed], findings)
	}
	if kinds[PatrolUnmanaged] != 1 {
		t.Errorf("unmanaged = %d, want 1; findings=%+v", kinds[PatrolUnmanaged], findings)
	}
}

// A known certificate the cloud reports as bound nowhere is drift (manual unbind).
func TestPatrolReportsUnboundKnownCertAsDrift(t *testing.T) {
	ForgetBindings("cert-gone")
	fake := &fakeSSLAPI{
		listCertsFn: func(context.Context, *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
			return &ssl.DescribeCertificatesResponse{
				Response: &ssl.DescribeCertificatesResponseParams{TotalCount: common.Uint64Ptr(0)},
			}, nil
		},
		createTaskFn: patrolCreateTask("t1", "cert-gone"),
		taskResultFn: patrolTaskResult("t1", 0),
	}
	d := patrolDeployer(t, fake)
	findings, err := d.PatrolBindings(context.Background(), []KnownCert{{Name: "www", DeployedID: "cert-gone"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Kind != PatrolDrift {
		t.Fatalf("want one drift finding, got %+v", findings)
	}
}

// An empty remark is the orphan-upload fingerprint (deploy died between upload and anchor).
func TestPatrolClassifiesEmptyRemarkAsOrphanUpload(t *testing.T) {
	fake := &fakeSSLAPI{
		listCertsFn: func(context.Context, *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
			return &ssl.DescribeCertificatesResponse{
				Response: &ssl.DescribeCertificatesResponseParams{
					TotalCount: common.Uint64Ptr(1),
					Certificates: []*ssl.Certificates{{
						CertificateId: common.StringPtr("cert-lost"),
						Alias:         common.StringPtr(""),
					}},
				},
			}, nil
		},
	}
	d := patrolDeployer(t, fake)
	findings, err := d.PatrolBindings(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Kind != PatrolOrphanUpload {
		t.Fatalf("want orphan_upload, got %+v", findings)
	}
}
