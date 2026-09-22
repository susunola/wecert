package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/tcerr"
)

type cachedBindings struct {
	snap BindingSnapshot
	at   time.Time
}

type bindingMemo struct {
	mu   sync.Mutex
	byID map[string]cachedBindings
}

var bindingMemoStore = &bindingMemo{byID: map[string]cachedBindings{}}

func rememberBindings(certID string, snap BindingSnapshot) {
	if certID == "" {
		return
	}
	bindingMemoStore.mu.Lock()
	bindingMemoStore.byID[certID] = cachedBindings{snap: snap, at: time.Now()}
	bindingMemoStore.mu.Unlock()
}

// LookupCachedBindings returns the last TaskDetail parse for certID and the
// instant it was observed, so the inventory page can timestamp rows that come
// from the cache instead of the current request. ok is false when this process
// has never successfully parsed one; at is then the zero time.
func LookupCachedBindings(certID string) (BindingSnapshot, time.Time, bool) {
	if certID == "" {
		return BindingSnapshot{}, time.Time{}, false
	}
	bindingMemoStore.mu.Lock()
	defer bindingMemoStore.mu.Unlock()
	hit, ok := bindingMemoStore.byID[certID]
	if !ok {
		return BindingSnapshot{}, time.Time{}, false
	}
	return hit.snap, hit.at, true
}

func (d *TencentCLB) Bindings(ctx context.Context, certID string) (int, bool, error) {
	if certID == "" {
		return 0, false, nil
	}
	client, err := d.client(ctx)
	if err != nil {
		return 0, false, err
	}
	n, err := d.bindingsWith(ctx, client, certID, true)
	return n.count, n.complete, err
}

func (d *LazyTencentCLB) Bindings(ctx context.Context, certID string) (int, bool, error) {
	if certID == "" {
		return 0, false, nil
	}
	inner, err := d.client()
	if err != nil {
		return 0, false, err
	}
	return inner.Bindings(ctx, certID)
}

func (d *TencentCLB) bindingsWith(ctx context.Context, client sslAPI, certID string, cached bool) (bindingCount, error) {
	cache := uint64(0)
	if cached {
		cache = 1
	}
	createReq := ssl.NewCreateCertificateBindResourceSyncTaskRequest()
	createReq.CertificateIds = []*string{common.StringPtr(certID)}
	createReq.IsCache = common.Uint64Ptr(cache)

	createResp, err := client.CreateCertificateBindResourceSyncTaskWithContext(ctx, createReq)
	if err != nil {
		return bindingCount{}, sdkCallError(ctx, "CreateCertificateBindResourceSyncTask", err)
	}
	if createResp.Response == nil || len(createResp.Response.CertTaskIds) == 0 {
		return bindingCount{complete: false}, nil
	}

	var taskID string
	for _, t := range createResp.Response.CertTaskIds {
		if t != nil && t.CertId != nil && *t.CertId == certID && t.TaskId != nil {
			taskID = *t.TaskId
			break
		}
	}
	if taskID == "" {
		return bindingCount{complete: false}, nil
	}

	deadline := d.now().Add(d.enumerationWait())
	var lastQueryErr error
	throttled := false
	for {
		queryReq := ssl.NewDescribeCertificateBindResourceTaskResultRequest()
		queryReq.TaskIds = []*string{common.StringPtr(taskID)}

		queryResp, err := client.DescribeCertificateBindResourceTaskResultWithContext(ctx, queryReq)
		if err != nil {
			if tcerr.IsPermanent(err) {
				return bindingCount{}, sdkCallError(ctx, "DescribeCertificateBindResourceTaskResult", err)
			}
			lastQueryErr = err
			if tcerr.IsThrottled(err) {
				throttled = true
			}
			d.log.Warn("failed to query the bind-resource enumeration; retrying within the budget",
				"certId", certID, "taskId", taskID, "err", err)
		} else {
			n, done, err := countBindings(queryResp, taskID)
			if err != nil {
				return bindingCount{}, err
			}
			if done {
				if !n.complete {
					d.log.Warn("the bind-resource enumeration finished with at least one region unanswered; the binding count is a lower bound",
						"certId", certID, "taskId", taskID, "boundResources", n.count)
				}
				d.rememberTaskDetail(ctx, client, certID, taskID)
				return n, nil
			}
		}

		if d.now().After(deadline) {
			if lastQueryErr != nil {
				return bindingCount{}, fmt.Errorf("the bind-resource enumeration did not finish within %s (taskId=%s); every poll failed, most recently: %w", d.enumerationWait(), taskID, lastQueryErr)
			}
			return bindingCount{}, fmt.Errorf("the bind-resource enumeration did not finish within %s (taskId=%s)", d.enumerationWait(), taskID)
		}
		if err := waitBetweenPolls(ctx, pollWait(2*time.Second, throttled)); err != nil {
			return bindingCount{}, err
		}
	}
}

type detailAPI interface {
	DescribeCertificateBindResourceTaskDetailWithContext(ctx context.Context, req *ssl.DescribeCertificateBindResourceTaskDetailRequest) (*ssl.DescribeCertificateBindResourceTaskDetailResponse, error)
}

func (d *TencentCLB) rememberTaskDetail(ctx context.Context, client sslAPI, certID, taskID string) {
	api, ok := client.(detailAPI)
	if !ok {
		return
	}
	req := ssl.NewDescribeCertificateBindResourceTaskDetailRequest()
	req.TaskId = common.StringPtr(taskID)
	req.ResourceTypes = []*string{common.StringPtr("clb")}
	resp, err := api.DescribeCertificateBindResourceTaskDetailWithContext(ctx, req)
	if err != nil {
		log := d.log
		if log == nil {
			log = slog.Default()
		}
		log.Warn("failed to read bind-resource task detail; inventory will keep the last cached rows",
			"certId", certID, "taskId", taskID, "err", err)
		return
	}
	rememberBindings(certID, ParseCLBBindingItems(resp, certID))
}
