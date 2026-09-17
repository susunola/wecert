package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
)

// TencentCLB uses the Tencent Cloud SSL certificate service to one-click update a
// certificate onto its bound CLB resources.
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

// enumerationWait is the effective bind-resource enumeration budget.
func (d *TencentCLB) enumerationWait() time.Duration {
	if d.enumerationBudget > 0 {
		return d.enumerationBudget
	}
	return defaultEnumerationBudget
}

// LazyTencentCLB creates the Tencent Cloud deployer only when an operation
// actually needs it. Desired-state documents can enable deployment after the
// process has started, while a document that keeps every certificate local
// should not require otherwise-unused static credentials at startup.
type LazyTencentCLB struct {
	cfg config.Tencent
	log *slog.Logger

	mu    sync.Mutex
	inner *TencentCLB
}

// NewLazyTencentCLB returns a deployer that defers credential validation and
// client construction until Deploy, Delete, or Bindings is first needed.
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

// Deploy implements Deployer.
func (d *LazyTencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	inner, err := d.client()
	if err != nil {
		return "", err
	}
	return inner.Deploy(ctx, certName, oldID, certPEM, keyPEM)
}

// Delete implements Deployer.
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

// Bindings implements Deployer.
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

// NewTencentCLB constructs the deployer.
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

// deployRecordGrace is how long a deploy record may report all-zero counters before the
// wait concludes that nothing was bound. See waitDeployRecord.
const deployRecordGrace = 15 * time.Second

// defaultEnumerationBudget is how long the bind-resource enumeration may take before the
// verification gives up and reports ErrSwitchUnverified instead of an answer.
//
// The enumeration is asynchronous and its latency belongs to the server, not to us:
// measured on a shared account holding 36 certificates, a task that was already cached
// answered in about 25s and fresh ones took longer than the 30s this used to allow --
// which turned an already-successful rebind into a failed pass on every attempt, with the
// state never recording the certificate that was serving traffic. The budget is generous
// on purpose: it costs one wait per deployment, and the alternative to waiting is a
// verification that never answers.
const defaultEnumerationBudget = 3 * time.Minute

// sslAPI is the narrow slice of the Tencent Cloud SSL client this package uses.
//
// *ssl.Client is a concrete struct with no interface seam, and client() rebuilds it
// on every call -- which left the polling logic in updateInstance and
// waitDeployRecord (the most failure-prone part of the package) impossible to
// unit-test. Declaring only the used methods as an interface lets tests substitute a
// fake while the production implementation stays the real SDK client.
//
// "Rebuilds it on every call" is literal: the SDK wraps each client in its own clone of
// http.DefaultTransport, so every deploy, reap and binding check opens a fresh TLS
// connection and leaves one idle for 30s. Reusing a client would be wrong for the other
// reason client() exists (credentials are fetched per call and the instance role's are
// temporary), and the SDK has no seam for injecting a shared transport: it applies
// ReqTimeout by mutating the client it is handed.
type sslAPI interface {
	UploadCertificateWithContext(ctx context.Context, req *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
	UpdateCertificateInstanceWithContext(ctx context.Context, req *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error)
	DescribeHostUpdateRecordDetailWithContext(ctx context.Context, req *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error)
	DeleteCertificateWithContext(ctx context.Context, req *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error)
	DescribeDeleteCertificatesTaskResultWithContext(ctx context.Context, req *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error)
	CreateCertificateBindResourceSyncTaskWithContext(ctx context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error)
	DescribeCertificateBindResourceTaskResultWithContext(ctx context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error)
}

// newSSLClient builds the production SSL API client.
//
// It is a package-level variable rather than a parameter of NewTencentCLB: that keeps
// the exported constructor (and its callers, e.g. internal/acme) unchanged while still
// letting tests swap in a fake.
var newSSLClient = func(cred common.CredentialIface) (sslAPI, error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	// The upload request body can be hundreds of KB, so the default timeout is not enough.
	cpf.HttpProfile.ReqTimeout = 60

	// The SSL certificate service is global, so pass an empty Region.
	return ssl.NewClient(cred, "", cpf)
}

// client resolves credentials and builds a client for the SSL certificate service.
func (d *TencentCLB) client(ctx context.Context) (sslAPI, error) {
	cred, err := d.credential(ctx)
	if err != nil {
		return nil, err
	}
	return newSSLClient(cred)
}

// waitBetweenPolls sleeps between polling iterations while still honoring context
// cancellation. It is a variable so tests can advance a fake clock instantly instead
// of waiting real seconds; production behavior is a plain interruptible sleep.
var waitBetweenPolls = func(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// Deploy uploads the new certificate and, when an old one exists, one-click updates every
// cloud resource bound to it.
func (d *TencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	newID, err := d.Upload(ctx, certName, certPEM, keyPEM)
	if err != nil {
		return "", err
	}
	return d.DeployUploaded(ctx, certName, oldID, newID)
}

// Upload stores the certificate and returns its durable Tencent Cloud identity.
func (d *TencentCLB) Upload(ctx context.Context, certName string, certPEM, keyPEM []byte) (string, error) {
	client, err := d.client(ctx)
	if err != nil {
		return "", err
	}
	return d.upload(ctx, client, certName, certPEM, keyPEM)
}

// DeployUploaded advances a previously uploaded certificate to its cloud binding.
func (d *TencentCLB) DeployUploaded(ctx context.Context, certName, oldID, newID string) (string, error) {
	client, err := d.client(ctx)
	if err != nil {
		return newID, err
	}
	return d.deployUploaded(ctx, client, certName, oldID, newID)
}

func (d *TencentCLB) deployUploaded(ctx context.Context, client sslAPI, certName, oldID, newID string) (string, error) {
	// First issuance: there is no "old certificate -> cloud resource" binding on the Tencent
	// Cloud side to look up, so after upload a human has to bind it once in the CLB console.
	// Every renewal after that is fully automatic.
	if oldID == "" {
		return newID, nil
	}

	// Note: on error, still hand back the newID that was already uploaded successfully.
	// The caller must record it in the reclamation list, otherwise this certificate becomes a
	// cloud orphan that occupies the account's uploaded-certificate quota forever.
	if err := d.updateInstance(ctx, client, oldID, newID); err != nil {
		// Nothing is bound to either certificate: this is not a failed switch, it is the
		// documented first-issuance state, reached on a renewal because the first upload was never
		// bound by hand.
		//
		// The distinction matters because the two look identical to the cloud
		// (FailedOperation.CertificateDeployInstanceEmpty) and call for opposite answers. Before
		// this, every renewal of a certificate nobody had bound yet failed the pass, so the
		// promotion never ran and st.NotAfter/CertPEM stayed on the certificate that was expiring:
		// the state kept naming a certificate whose only remaining future was to expire, and each
		// failed cycle issued and uploaded another one.
		//
		// Both answers must be COMPLETE for this reading: a partial enumeration reports 0 for a
		// certificate that is bound in a region the read could not reach, and treating that as
		// "nothing is bound" is how a needed switch gets skipped and a listener keeps serving a
		// certificate that is about to expire.
		if d.nothingBoundYet(ctx, client, oldID, newID) {
			d.log.Warn("neither the old nor the new certificate is bound to anything yet; "+
				"recording the new one as uploaded and waiting for the one-time manual bind",
				"oldCertId", oldID, "newCertId", newID)
			return newID, ErrNothingBoundYet
		}
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
		// cached=false on both: this decides whether a switch took effect, and the SDK's cache can
		// answer from a completed task up to half an hour old.
		if n, nerr := d.bindingsWith(ctx, client, newID, false); nerr == nil && n.count > 0 {
			// oldBindings == 0 is the load-bearing half, so it must come from a COMPLETE answer.
			// A partial enumeration that skipped a failed region also produces 0, and reading that
			// as "the old certificate is bound nowhere" is exactly how a half-finished switch gets
			// recorded as done -- with some listeners still serving the old certificate and nothing
			// left to revisit them.
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

// ResumeDeploy never uploads. It first observes whether the already-uploaded
// certificate became live after the caller timed out; otherwise it resumes the
// cloud-side update using that same certificate ID.
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
	// Allow re-uploading a certificate with the same fingerprint: otherwise a single upload
	// retry fails outright.
	req.Repeatable = common.BoolPtr(true)

	resp, err := client.UploadCertificateWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("UploadCertificate: %w", err)
	}
	if resp.Response == nil {
		return "", errors.New("UploadCertificate returned an empty response")
	}

	// RepeatCertId is the ID of an existing copy. The SDK documents that when the same
	// certificate has been uploaded more than 5000 times the API ignores Repeatable=true and
	// returns the duplicate's ID here instead of creating another copy.
	//
	// That copy is the same certificate, so its ID is a usable answer -- and ignoring the
	// field turned the case into "UploadCertificate returned no CertificateId", which names
	// neither the cause nor the fix. Only reached when CertificateId is absent, so the
	// normal path is untouched.
	if id := derefStr(resp.Response.CertificateId); id != "" {
		return id, nil
	}
	if dup := derefStr(resp.Response.RepeatCertId); dup != "" {
		return dup, nil
	}
	return "", errors.New("UploadCertificate returned neither a CertificateId nor a " +
		"RepeatCertId; the certificate was not stored")
}

// updateInstance calls UpdateCertificateInstance to do the one-click update.
//
// The API is asynchronous and has a rather unintuitive convention: DeployRecordId == 0
// means the task is still being created, so the request must be repeated until it is > 0
// before creation counts as successful.
// DeployStatus == 0 means "a task is already in progress", which is naturally idempotent.
func (d *TencentCLB) updateInstance(ctx context.Context, client sslAPI, oldID, newID string) error {
	req := ssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = common.StringPtr(oldID)
	req.CertificateId = common.StringPtr(newID)
	req.ResourceTypes = toPtrSlice(d.types)
	req.ResourceTypesRegions = d.resourceTypeRegions()
	// 1 = ignore the old certificate's expiry reminder. Without this, the old certificate
	// keeps firing expiry alerts even after a successful renewal.
	req.ExpiringNotificationSwitch = common.Uint64Ptr(1)

	deadline := d.now().Add(2 * time.Minute)
	// Mind the type: DeployRecordId in the UpdateCertificateInstance response is *uint64
	// (the SDK has several same-named fields elsewhere that are *int64 -- do not copy that).
	var recordID uint64
	for {
		resp, err := client.UpdateCertificateInstanceWithContext(ctx, req)
		if err != nil {
			return fmt.Errorf("UpdateCertificateInstance: %w", err)
		}
		if resp.Response != nil && resp.Response.DeployRecordId != nil && *resp.Response.DeployRecordId > 0 {
			recordID = *resp.Response.DeployRecordId
			progress := resp.Response.UpdateSyncProgress
			bound, progressReady := progressBoundCount(progress)

			// DeployStatus distinguishes "this request created the task" from "a task is
			// already running and this is its ID": the SDK documents 1 as created, 0 as
			// "there is already an update in progress, no new task was created, and the
			// returned DeployRecordId is that in-progress task's".
			//
			// Adopting a pre-existing task blindly is dangerous because it may belong to a
			// different switch (for example the previous round's oldID -> X task, which this
			// code abandoned after its own 3-minute wait). When it later succeeds,
			// waitDeployRecord returns nil and Deploy reports newID as deployed while the
			// cloud is serving X. The 1-minute manager backoff against the 3-minute wait
			// makes that overlap reachable.
			//
			// Only an explicit 0 counts as "adopted": a nil DeployStatus is a missing answer
			// from an older API version, not the answer "an existing task", and treating it
			// as adopted would add a verification round trip for everyone.
			//
			// So an adopted task is waited on and then verified the only way that answers
			// the question that matters: is THIS certificate bound anywhere?
			if resp.Response.DeployStatus != nil && *resp.Response.DeployStatus == 0 {
				verifyStart := d.now()
				d.log.Warn("another update task is already in progress; waiting for it and then "+
					"verifying that this certificate is the one that got bound",
					"oldCertId", oldID, "newCertId", newID, "deployRecordId", recordID)
				if werr := d.waitDeployRecord(ctx, client, recordID, oldID); werr != nil {
					return werr
				}
				// cached=false: the question is whether THIS certificate is bound right now, and a
				// cached task result from before the switch answers a different question.
				n, berr := d.bindingsWith(ctx, client, newID, false)
				if berr != nil {
					// The task is done and the record says it succeeded, but the enumeration that
					// would confirm which certificate ended up bound did not answer in time. That is
					// "unknown", not "failed" -- see ErrSwitchUnverified for why failing here never
					// converges.
					return fmt.Errorf("%w: the in-progress update task finished, but enumerating the "+
						"bindings of %s failed: %v", ErrSwitchUnverified, newID, berr)
				}
				if n.count == 0 && !n.complete {
					// Not the same as "it is not bound": at least one region went unanswered, so
					// this program cannot tell. Reporting failure here would be wrong about a
					// switch that did happen, and reporting success would be wrong about one that
					// did not -- so it reports the uncertainty and lets the binding probe settle it.
					return fmt.Errorf("%w: an update task was already in progress and finished, but the "+
						"bind-resource enumeration for %s did not cover every region", ErrSwitchUnverified, newID)
				}
				if n.count == 0 {
					return fmt.Errorf("an update task was already in progress, and this certificate (%s) is "+
						"not bound to any resource afterwards; the task belonged to a different switch, so "+
						"this deploy did not happen", newID)
				}
				// Say how long the verification took. It is bounded by the record wait (3m) plus the
				// enumeration budget (3m), so a pass can legitimately spend minutes here, and without
				// this line a slow verification is indistinguishable from a hung one in the journal.
				// It is the same path that used to fail whenever the enumeration was slower than 30s,
				// so the number is also the evidence that the budget is now adequate.
				d.log.Info("verified the adopted update task",
					"oldCertId", oldID, "newCertId", newID, "deployRecordId", recordID,
					"boundResources", n.count, "took", d.now().Sub(verifyStart).Round(time.Second))
				return nil
			}

			d.log.Info("one-click update task created",
				"oldCertId", oldID, "newCertId", newID,
				"deployRecordId", recordID,
				"boundResources", bound,
				"progress", formatProgress(progress))

			// `bound` is only an answer when the server actually sent progress.
			//
			// An empty UpdateSyncProgress is a **missing** answer, not the answer "zero".
			// The API creates the task and reports per-region progress separately, and on
			// the response that first carries a DeployRecordId it is routinely still
			// absent -- observed in production: the task was created (recordId=14822) with
			// no progress detail, wecert read that as "nothing is bound" and failed the
			// rebind, and the cloud finished switching the listener 47 seconds later.
			//
			// That failure is not self-correcting. wecert keeps the old certificate as its
			// anchor, the old certificate has no bindings left because the switch *did*
			// happen, so every later round uploads another certificate, fails the same way,
			// and records another orphan -- while the certificate actually serving traffic
			// sits in retired_certificates, protected only by the cloud-side resource check.
			//
			// So a populated response reporting zero still refuses (that really is "nothing
			// bound"), and an unpopulated one defers to the task record, which is
			// authoritative.
			//
			// progressReady is the precise form of "populated": it is a null TotalCount,
			// not an empty progress list, that carries the ambiguity -- a response can list
			// regions and still have no count for any of them, or for only some of them.
			if bound == 0 && progressReady {
				return noResourceBoundError(oldID, d.regions)
			}
			if bound == 0 && !progressReady {
				d.log.Warn("the sync progress carries no per-region count yet; "+
					"deferring to the async deploy record to decide whether anything was bound",
					"oldCertId", oldID, "newCertId", newID, "deployRecordId", recordID)
			}
			return d.waitDeployRecord(ctx, client, recordID, oldID)
		}
		if d.now().After(deadline) {
			return fmt.Errorf("the UpdateCertificateInstance task was not created within 2m (there may be one already running)")
		}
		if err := waitBetweenPolls(ctx, 3*time.Second); err != nil {
			return err
		}
	}
}

// waitDeployRecord waits for the one-click update task to actually finish.
//
// UpdateCertificateInstance returning only means the task was created; the rebinding
// happens asynchronously in the background. Setting DeployConfirmed without waiting for it
// to finish writes the most insidious failure mode -- "the program thinks it succeeded
// while nothing actually took effect" -- into the state database.
func (d *TencentCLB) waitDeployRecord(ctx context.Context, client sslAPI, recordID uint64, oldID string) error {
	deadline := d.now().Add(3 * time.Minute)

	// The counters live outside the loop and are updated only on a successful query, so
	// they always hold the last *known* state. If the final polls before the deadline all
	// errored, the deadline branch below must still see that state -- reading zeros there
	// misdiagnoses a task that was making progress as "no resource bound to the old
	// certificate" and sends the operator off to check a listener that is fine.
	var success, failed, running, pending int64

	// Between the task being created and the server marking it running, every counter is
	// zero. Concluding "no resource is bound" from that instant would repeat the very
	// mistake this path exists to absorb, so the zero-resource verdict waits for a short
	// grace period first -- long enough for a task that has work to show it, short enough
	// that a genuinely unbound certificate is still diagnosed promptly rather than after
	// the full three minutes.
	graceUntil := d.now().Add(deployRecordGrace)
	for {
		s, f, r, p, instrumented, err := d.describeDeployRecord(ctx, client, recordID)
		if err != nil {
			d.log.Warn("failed to query the deploy record; retrying shortly", "deployRecordId", recordID, "err", err)
		} else if !instrumented {
			// The record detail has the same async-population hazard as the sync
			// progress: the counter fields are pointers in the SDK and are null until
			// the server instruments the task, and null is not zero. Reading nulls as
			// zeros would let the zero-resource verdict fire against a task that has
			// not even been measured yet, so an uninstrumented answer is no answer:
			// keep waiting (the deadline below still bounds the wait).
			d.log.Info("the deploy record carries no counters yet; waiting for the server to instrument the task",
				"deployRecordId", recordID)
		} else {
			success, failed, running, pending = s, f, r, p
			d.log.Info("one-click update progress",
				"deployRecordId", recordID,
				"success", success, "failed", failed, "running", running, "pending", pending)

			// Pending counts as unfinished. Resources are queued before they run, so
			// "nothing is running" can be true while most of the task has not started --
			// declaring success there means retiring the old certificate while listeners
			// still serve it.
			if running == 0 && pending == 0 && (success+failed) > 0 {
				if failed > 0 {
					return fmt.Errorf("one-click update finished with %d resources failed (%d succeeded)", failed, success)
				}
				return nil
			}

			// Settled and updated nothing: the old certificate really is bound to no
			// resource. This is the verdict the sync response defers here when its
			// per-region TotalCount had not been populated yet.
			if running == 0 && pending == 0 && success == 0 && failed == 0 && d.now().After(graceUntil) {
				return noResourceBoundError(oldID, d.regions)
			}
		}
		if d.now().After(deadline) {
			return fmt.Errorf("one-click update task %d did not finish within 3m (success=%d failed=%d running=%d pending=%d)",
				recordID, success, failed, running, pending)
		}
		if err := waitBetweenPolls(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}

// describeDeployRecord queries the resource-level detail of a deploy record once.
//
// instrumented reports whether the server has populated the counters at all: the SDK
// exposes every TotalCount field as a pointer, and they are null until the task is
// instrumented server-side -- the same async-population behavior as the sync progress.
// A null counter must not be dereferenced into a zero that the zero-resource verdict
// would then mistake for a real answer; when any counter is null the whole response is
// reported as not instrumented and the caller keeps waiting.
func (d *TencentCLB) describeDeployRecord(ctx context.Context, client sslAPI, recordID uint64) (success, failed, running, pending int64, instrumented bool, err error) {
	req := ssl.NewDescribeHostUpdateRecordDetailRequest()
	req.DeployRecordId = common.StringPtr(strconv.FormatUint(recordID, 10))
	resp, err := client.DescribeHostUpdateRecordDetailWithContext(ctx, req)
	if err != nil {
		return 0, 0, 0, 0, false, err
	}
	if resp.Response == nil {
		return 0, 0, 0, 0, false, errors.New("DescribeHostUpdateRecordDetail returned an empty response")
	}
	r := resp.Response
	if r.SuccessTotalCount == nil || r.FailedTotalCount == nil || r.RunningTotalCount == nil || r.PendingTotalCount == nil {
		return 0, 0, 0, 0, false, nil
	}
	return *r.SuccessTotalCount, *r.FailedTotalCount, *r.RunningTotalCount, *r.PendingTotalCount, true, nil
}

// resourceTypeRegions expands the region list per resource type.
// Resources such as CLB are regional, so omitting regions means not one instance gets
// updated.
func (d *TencentCLB) resourceTypeRegions() []*ssl.ResourceTypeRegions {
	out := make([]*ssl.ResourceTypeRegions, 0, len(d.types))
	for _, t := range d.types {
		out = append(out, &ssl.ResourceTypeRegions{
			ResourceType: common.StringPtr(t),
			Regions:      toPtrSlice(d.regions),
		})
	}
	return out
}

// Delete removes a retired certificate.
//
// This step is not optional: Tencent Cloud accounts have a quota on uploaded certificates,
// and long-running automation that never reclaims old certificates will eventually hit the
// quota and be unable to renew.
func (d *TencentCLB) Delete(ctx context.Context, certID string) error {
	if certID == "" {
		return nil
	}
	client, err := d.client(ctx)
	if err != nil {
		return err
	}

	req := ssl.NewDeleteCertificateRequest()
	req.CertificateId = common.StringPtr(certID)
	// true = have the server still check associated resources: refuse the delete as long as
	// any cloud resource still references this certificate.
	// This is more conservative than "we track bindings ourselves and skip the check" -- the
	// cost of a failed delete is a held quota slot, while the cost of a mistaken delete is
	// production HTTPS going down. The two are not equivalent.
	// When the delete fails, ReapRetired logs a warning and retries next round.
	req.IsCheckResource = common.BoolPtr(true)

	resp, err := client.DeleteCertificateWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DeleteCertificate(%s): %w", certID, err)
	}
	if resp.Response == nil {
		return fmt.Errorf("DeleteCertificate(%s): the API returned an empty response", certID)
	}

	// IsCheckResource=true makes the delete ASYNCHRONOUS: the SDK documents that
	// choosing the check makes the deletion asynchronous, that the call returns an
	// async task ID, and that DescribeDeleteCertificatesTaskResult is the interface
	// that says whether the deletion succeeded. Returning nil here for a call that was
	// merely *accepted* would make ReapRetired drop its reclaim record, so the
	// certificate would leak in the cloud account forever -- and the exact case the
	// resource check exists for (a live certificate still bound to a listener) is
	// reported asynchronously as status 4, which would never be seen.
	if resp.Response.DeleteResult != nil && !*resp.Response.DeleteResult {
		return fmt.Errorf("DeleteCertificate(%s): the API refused the delete", certID)
	}
	if resp.Response.TaskId == nil || *resp.Response.TaskId == "" {
		// Synchronous answer: DeleteResult (nil means "no objection") is the whole result.
		return nil
	}
	return d.waitDeleteTask(ctx, client, *resp.Response.TaskId, certID)
}

// How long to wait for an asynchronous delete task, and how often to ask.
const (
	deleteTaskTimeout = 2 * time.Minute
	deleteTaskPoll    = 3 * time.Second
)

// delete task status values, from the SDK's DeleteTaskResult.Status:
//
//	0 in progress, 1 succeeded, 2 failed, 3 failed for lack of the service role,
//	4 failed because an un-released cloud resource still references the certificate,
//	5 failed because the binding query timed out.
const (
	deleteTaskRunning = 0
	deleteTaskSuccess = 1
)

// waitDeleteTask polls until the delete really happened, and reports a failure otherwise.
//
// Status 4 is the one that matters most: it is the server saying "a resource still
// references this certificate", which must keep the reclaim record so the next round
// tries again once the reference is gone.
func (d *TencentCLB) waitDeleteTask(ctx context.Context, client sslAPI, taskID, certID string) error {
	deadline := d.now().Add(deleteTaskTimeout)

	for {
		req := ssl.NewDescribeDeleteCertificatesTaskResultRequest()
		req.TaskIds = []*string{common.StringPtr(taskID)}
		resp, err := client.DescribeDeleteCertificatesTaskResultWithContext(ctx, req)
		if err != nil {
			return fmt.Errorf("DescribeDeleteCertificatesTaskResult(%s): %w", taskID, err)
		}

		status, detail, found, err := deleteTaskStatus(resp, taskID)
		if err != nil {
			return err
		}
		if found && status != deleteTaskRunning {
			if status == deleteTaskSuccess {
				return nil
			}
			return fmt.Errorf("DeleteCertificate(%s) failed: task %s reported status %d%s",
				certID, taskID, status, detail)
		}

		if d.now().After(deadline) {
			return fmt.Errorf(
				"the delete task for %s did not finish within %s (taskId=%s); keeping it on the reclaim list to retry",
				certID, deleteTaskTimeout, taskID)
		}
		if err := waitBetweenPolls(ctx, deleteTaskPoll); err != nil {
			return err
		}
	}
}

// deleteTaskStatus extracts one task's status out of a query response.
//
// found=false means the response carried no entry for this task yet, which is "still
// working on it" rather than a failure.
func deleteTaskStatus(
	resp *ssl.DescribeDeleteCertificatesTaskResultResponse, taskID string,
) (status uint64, detail string, found bool, err error) {
	if resp == nil || resp.Response == nil {
		return 0, "", false, nil
	}

	for _, r := range resp.Response.DeleteTaskResult {
		if r == nil || r.TaskId == nil || *r.TaskId != taskID {
			continue
		}
		if r.Status == nil {
			return 0, "", false, nil
		}
		d := ""
		if r.Error != nil && *r.Error != "" {
			d = ": " + *r.Error
		}
		return *r.Status, d, true, nil
	}
	return 0, "", false, nil
}

func toPtrSlice(in []string) []*string {
	out := make([]*string, 0, len(in))
	for _, s := range in {
		out = append(out, common.StringPtr(s))
	}
	return out
}

// progressBoundCount counts how many resources this one-click update covers in total,
// and reports whether the server has populated that detail yet.
//
// A count of zero used to be read on its own as "no resource bound to the old
// certificate", i.e. the certificate was never actually bound -- the failure mode most
// easily overlooked. But `UpdateSyncProgressRegions[].TotalCount` is filled in
// asynchronously, so on the response that first carries a DeployRecordId it can still be
// **null**, and null is not zero: the task was created and may well be switching the
// listener right now.
//
// `ready` separates the two, and it demands the *whole* answer: every listed region must
// carry a real TotalCount. A partially populated response (region A counted, region B
// still null) is no more authoritative than an empty one -- the new task may be
// switching region B at that very moment, and summing only the populated regions would
// report a zero that is not real. Only when every region has answered is a zero the
// genuine no-binding case.
func progressBoundCount(progress []*ssl.UpdateSyncProgress) (count int64, ready bool) {
	var n int64
	listed := 0
	answered := 0
	// An entry -- or a region -- that is present but says nothing is an UNANSWERED part of the
	// response, not an absent one. Counting only what was listed made a half-populated answer read
	// as a finished one, and a finished answer of zero is what licenses the caller's hard
	// noResourceBoundError branch instead of deferring to the authoritative deploy record. Same
	// shape as countBindings, which was fixed for exactly this.
	unanswered := 0
	for _, p := range progress {
		// The SDK hands back []*T; a nil element is not a "region with no count", it is a
		// missing entry, and dereferencing it panics inside updateInstance -- after the
		// certificate was already uploaded. reconcileOne recovers the panic, so the process
		// survives, but recordFailure never runs: no backoff, no last_error, and the deploy
		// never completes. Every other SDK list in this file is guarded; these two were not.
		if p == nil {
			unanswered++
			continue
		}
		if len(p.UpdateSyncProgressRegions) == 0 {
			// The resource type came back with no regions at all: whatever it was bound to is not
			// in this answer.
			unanswered++
		}
		for _, r := range p.UpdateSyncProgressRegions {
			if r == nil {
				unanswered++
				continue
			}
			listed++
			if r.TotalCount != nil {
				answered++
				n += *r.TotalCount
			}
		}
	}
	return n, listed > 0 && answered == listed && unanswered == 0
}

// noResourceBoundError is the diagnosis shared by the two places that can conclude the
// old certificate was bound to nothing: a populated sync response reporting zero, and an
// async task that settles having updated nothing.
//
// Deploy's recovery path does not key on this error. It keys on the shape instead -- the new
// certificate bound and the old one not -- which distinguishes "the switch happened and was
// not recorded" from "the task partly failed" without having to classify the failure.
func noResourceBoundError(oldID string, regions []string) error {
	return fmt.Errorf("UpdateCertificateInstance found no resource bound to the old certificate %s (regions=%v); refusing to mark the new certificate as deployed. Check that the CLB listener has it bound (an SNI listener must use multi_cert_info; the primary certificate_id is silently ignored)",
		oldID, regions)
}

// formatProgress summarizes UpdateCertificateInstance progress into a single line.
func formatProgress(progress []*ssl.UpdateSyncProgress) string {
	if len(progress) == 0 {
		return "(the server returned no progress detail)"
	}
	var parts []string
	for _, p := range progress {
		if p == nil {
			continue
		}
		for _, r := range p.UpdateSyncProgressRegions {
			if r == nil {
				continue
			}
			parts = append(parts,
				fmt.Sprintf("%s/%s total=%d status=%d",
					derefStr(p.ResourceType), derefStr(r.Region), derefI64(r.TotalCount), derefI64(r.Status)))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("(%d resource types, but no per-region detail)", len(progress))
	}
	return strings.Join(parts, "; ")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// Bindings queries how many cloud resources this certificate is currently bound to.
//
// This is read-only: CreateCertificateBindResourceSyncTask creates an enumeration task and
// the result is then fetched by TaskId. Deliberately not using UpdateCertificateInstance to
// "probe" the state, because that is a write operation and confirming a binding must not
// produce side effects.
//
// Why it is needed: first issuance only uploads and does not bind, so DeployConfirmed is
// false. After a human binds it in the console there used to be no path back to set it --
// the deployed metric would report "not deployed" for the whole certificate cycle (up to 90
// days for classic) even though the certificate was serving traffic the entire time.
func (d *TencentCLB) Bindings(ctx context.Context, certID string) (int, bool, error) {
	if certID == "" {
		return 0, false, nil
	}
	client, err := d.client(ctx)
	if err != nil {
		return 0, false, err
	}
	// cached=true: this is the periodic "has a human bound it yet" poll. See bindingsWith.
	n, err := d.bindingsWith(ctx, client, certID, true)
	return n.count, n.complete, err
}

// bindingCount is how many cloud resources a certificate is bound to, and whether that number is
// the whole answer.
//
// The zero is load-bearing and that is the entire reason this is not a plain int. DeployUploaded's
// repair path reads "the old certificate has 0 bindings" as "the switch happened but was not
// recorded" and reports success on it; and the adoption path reads "0" as "the task belonged to a
// different switch, so this deploy did not happen". Neither may be concluded from an answer this
// program could not fully obtain -- a region whose query failed, a response with no task id, an
// empty CertTaskIds list. Whenever complete is false, count is a LOWER BOUND: a non-zero count still
// proves something is bound, but a zero proves nothing at all.
type bindingCount struct {
	count    int
	complete bool
}

// ErrNothingBoundYet means the certificate was uploaded, but neither it nor the certificate it
// replaces is bound to any cloud resource.
//
// It is the documented first-issuance state ("upload once, bind it by hand once, renewals switch
// automatically afterwards") met during a renewal, and it is deliberately not a failure: there was
// no switch to perform. Callers must record the new certificate id and leave DeployConfirmed false,
// so the deployed metric keeps saying "uploaded, not serving yet" until the enumeration finds it.
var ErrNothingBoundYet = errors.New("the certificate is uploaded but nothing is bound to it yet")

// nothingBoundYet reports whether BOTH certificates have zero bindings, from complete answers.
func (d *TencentCLB) nothingBoundYet(ctx context.Context, client sslAPI, oldID, newID string) bool {
	newBindings, nerr := d.bindingsWith(ctx, client, newID, false)
	if nerr != nil || !newBindings.complete || newBindings.count > 0 {
		return false
	}
	oldBindings, oerr := d.bindingsWith(ctx, client, oldID, false)
	return oerr == nil && oldBindings.complete && oldBindings.count == 0
}

// bindingsWith enumerates a certificate's bindings against an existing client.
//
// Split out so Deploy's recovery path can reuse it: that path already holds a client,
// and rebuilding one would mean a second credential fetch and TLS setup.
// cached selects the server-side cache. The SDK documents it as: with IsCache=1, if a completed
// task exists for this certificate within the last half hour, the query result closest to now
// *within that half hour* is returned. That is fine for the periodic "has a human bound it yet"
// poll, which is why that one asks for it -- and wrong for the two calls that decide whether a
// switch took effect, because a result from up to half an hour ago cannot answer "is it bound
// now". Those pass cached=false.
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
		return bindingCount{}, fmt.Errorf("CreateCertificateBindResourceSyncTask: %w", err)
	}
	// No task ids is not the answer "bound nowhere": it is the absence of an answer, and an older
	// API version or a throttled call both look like this.
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
		// Same reasoning as above: this certificate was in the list but carried no task id, so
		// there is no enumeration to read.
		return bindingCount{complete: false}, nil
	}

	// Enumeration is asynchronous, so poll until there is a result. The ceiling comes from
	// enumerationWait: this is only a confirmation action, but a budget shorter than the
	// server's own latency produces a verification that never answers, which is worse than
	// waiting (see defaultEnumerationBudget).
	deadline := d.now().Add(d.enumerationWait())
	for {
		queryReq := ssl.NewDescribeCertificateBindResourceTaskResultRequest()
		queryReq.TaskIds = []*string{common.StringPtr(taskID)}

		queryResp, err := client.DescribeCertificateBindResourceTaskResultWithContext(ctx, queryReq)
		if err != nil {
			return bindingCount{}, fmt.Errorf("DescribeCertificateBindResourceTaskResult: %w", err)
		}

		n, done, err := countBindings(queryResp, taskID)
		if err != nil {
			return bindingCount{}, err
		}
		if done {
			if !n.complete {
				// The task finished, but at least one region's query failed inside it. Polling
				// again is not obviously better -- the region error is not a "not ready yet"
				// signal -- so the caller gets the lower bound and decides. For the confirmation
				// poll a non-zero count still confirms; for the two verification calls a zero
				// from an incomplete answer is refused rather than believed.
				d.log.Warn("the bind-resource enumeration finished with at least one region "+
					"unanswered; the binding count is a lower bound",
					"certId", certID, "taskId", taskID, "boundResources", n.count)
			}
			return n, nil
		}

		if d.now().After(deadline) {
			return bindingCount{}, fmt.Errorf("the bind-resource enumeration did not finish within %s (taskId=%s)",
				d.enumerationWait(), taskID)
		}
		if err := waitBetweenPolls(ctx, 2*time.Second); err != nil {
			return bindingCount{}, err
		}
	}
}

// bindStatusDone is the Status value when the enumeration task has completed.
//
// This value has no public documentation; it was determined empirically (see the
// countBindings comment below).
const bindStatusDone = 1

// countBindings counts the total number of bound resources out of the query result.
//
// A return value of done=false means the task has no result yet and the caller should keep
// waiting.
//
// On the meaning of Status: **empirically, Status == 1 means success**.
// I first wrote "Status != 0 means not ready yet" on intuition, and the confirmation then
// never saw a result -- this field's meaning cannot be guessed, so the empirical finding is
// recorded here.
//
// BindResourceResult must also be required to be non-empty: the first query (before the
// server-side cache exists) returns an object whose TaskId matches but whose result list is
// empty. Checking only TaskId would conclude "0 bindings" at that instant and judge a
// perfectly well-bound certificate as unbound.
func countBindings(
	resp *ssl.DescribeCertificateBindResourceTaskResultResponse, taskID string,
) (count bindingCount, done bool, err error) {
	if resp == nil || resp.Response == nil {
		return bindingCount{}, false, nil
	}

	for _, r := range resp.Response.SyncTaskBindResourceResult {
		if r == nil || r.TaskId == nil || *r.TaskId != taskID {
			continue
		}

		// Do not keep waiting idly when the server reports an explicit error.
		if r.Error != nil && r.Error.Message != nil && *r.Error.Message != "" {
			return bindingCount{}, false, fmt.Errorf("bind-resource task %s failed: %s", taskID, *r.Error.Message)
		}

		// Either not finished yet, or finished but the result list is not populated yet --
		// keep waiting in both cases.
		if r.Status == nil || *r.Status != bindStatusDone || len(r.BindResourceResult) == 0 {
			return bindingCount{}, false, nil
		}

		total := 0
		complete := true
		for _, res := range r.BindResourceResult {
			if res == nil {
				// A resource-type entry with no body counted nothing. Treating that as an answered
				// enumeration is how a total of zero becomes authoritative: the repair path reads
				// "complete && count == 0" as "the old certificate is gone" and reports the switch
				// as done. The empty outer list is refused above for the same reason, one level up.
				complete = false
				continue
			}
			if len(res.BindResourceRegionResult) == 0 {
				// Same shape one level down: the entry exists but no region was counted, so the
				// zero is a missing answer rather than the number zero.
				complete = false
			}
			for _, region := range res.BindResourceRegionResult {
				// A region that is absent from the answer, or that carries no TotalCount, is a
				// region this enumeration did not count. Skipping it silently made the total read
				// as a finished answer and, when it happened to be the only region, as the number
				// zero -- which the repair path treats as "the old certificate is gone".
				if region == nil || region.TotalCount == nil {
					complete = false
					continue
				}
				if region.Error != nil && *region.Error != "" {
					// The region's query failed, so its resources are missing from the total.
					// This is what the comment always claimed to do and the code did not: the
					// count is reported as a lower bound instead of as the answer.
					complete = false
					continue
				}
				total += int(*region.TotalCount)
			}
		}
		return bindingCount{count: total, complete: complete}, true, nil
	}

	return bindingCount{}, false, nil
}
