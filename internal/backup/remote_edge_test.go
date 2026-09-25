package backup

// This file covers the remote-backup paths whose wrong answer is silent. Retention is
// the clearest case: "the upload succeeded" and "the recovery points an operator still
// has" are different questions, and only the second one matters after state.db is lost.
// So these tests assert *which objects were deleted*, not just the returned error. The
// same reasoning drives the rest: a restore must only ever consider this installation's
// snapshot names, a signature that does not verify must leave nothing behind that a
// later reader could mistake for a snapshot, a credential that cannot be resolved must
// fail before anything is published, and a remote that never answers must not outlive
// the configured timeout.
//
// The harnesses in remote_test.go -- the local S3-compatible HTTP endpoint and the
// SSH/SFTP server -- are reused. The S3 fake is extended here to record requests,
// because "deleted with single-object DELETEs" (COS) and "deleted in one multi-object
// call" (S3) are behaviour, not implementation detail: COS rejects the payload S3
// accepts. The SFTP server is generalised over the subsystem it serves for one test:
// the case where the object is on the remote but retention cannot run.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	fakeBucket  = "bucket"
	fakePrefix  = "wecert"
	fakeBase    = "state.db"
	s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"
)

// fakeS3Store is an in-memory S3-compatible endpoint that also records every request.
// Retention assertions need the log: a test that only checks the surviving local file
// cannot tell "the old snapshot was deleted" from "the old snapshot was never listed".
type fakeS3Store struct {
	mu         sync.Mutex
	objects    map[string][]byte
	log        []string // "METHOD request-uri", in order
	deleted    []string // keys the server actually removed, in order
	accessKeys []string // SigV4 access key id of each signed request, in order

	// Fault injection. Each one reproduces a real gateway answer, not a crash.
	headLen    *int64 // HEAD answers this Content-Length instead of the real size
	headBare   bool   // HEAD answers 200 with no Content-Length header at all
	getFail    bool   // GET answers 404
	listFail   bool   // GET listing answers 500
	deleteFail bool   // DELETEs and the multi-object delete answer 500
	pageSize   int    // non-zero: ListObjects V1 answers one page of this many keys
	markers    []string
	stall      bool // every request blocks until the client gives up

	// release ends a stalled request. A stalled handler cannot rely on the client's
	// disconnect alone: the connection stays open, the request context stays live, and
	// httptest.Server.Close would wait for the handler forever -- a test that hangs in
	// cleanup instead of failing is worse than no test.
	release chan struct{}

	srv *httptest.Server
}

func newFakeS3Store(t *testing.T) *fakeS3Store {
	t.Helper()
	f := &fakeS3Store{objects: map[string][]byte{}, release: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	// Registered last, so it runs first: the stalled handler must return before the
	// server starts waiting for it.
	t.Cleanup(func() { close(f.release) })
	return f
}

func (f *fakeS3Store) endpoint() string { return f.srv.URL }

func (f *fakeS3Store) put(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = body
}

func (f *fakeS3Store) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[key]
	return body, ok
}

func (f *fakeS3Store) has(key string) bool {
	_, ok := f.get(key)
	return ok
}

// keys returns the object names in lexicographic order, which is the order S3 lists
// them in and the order retention sorts by.
func (f *fakeS3Store) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for name := range f.objects {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (f *fakeS3Store) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

// countRequests returns how many recorded requests start with method+" ".
func (f *fakeS3Store) countRequests(method string) int {
	n := 0
	for _, entry := range f.requests() {
		if strings.HasPrefix(entry, method+" ") {
			n++
		}
	}
	return n
}

// signedAccessKeys returns the credential access key id of every SigV4-signed request.
// It is how a test proves which environment variable the object-store code actually
// read, rather than only that it did not fail.
func (f *fakeS3Store) signedAccessKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.accessKeys...)
}

func (f *fakeS3Store) remove(key string) {
	delete(f.objects, key)
	f.deleted = append(f.deleted, key)
}

func (f *fakeS3Store) isList(r *http.Request) bool {
	if r.URL.Query().Has("prefix") {
		return true
	}
	return r.URL.Path == "/"+fakeBucket || r.URL.Path == "/"+fakeBucket+"/"
}

func (f *fakeS3Store) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.log = append(f.log, r.Method+" "+r.URL.RequestURI())
	if key := accessKeyOf(r); key != "" {
		f.accessKeys = append(f.accessKeys, key)
	}
	stall := f.stall
	f.mu.Unlock()
	if stall {
		// A request that never completes on its own. Only the caller's deadline can end
		// this, which is exactly what the timeout tests assert.
		select {
		case <-r.Context().Done():
		case <-f.release:
		}
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/"+fakeBucket+"/")
	switch {
	case r.Method == http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// The AWS SDK may frame the body (aws-chunked); a real bucket decodes it. Nothing
		// here asserts the wire body, only that what was stored can be read back, so
		// store the bytes the SDK sent.
		f.put(key, body)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		f.mu.Lock()
		fail := f.deleteFail
		if !fail {
			f.remove(key)
		}
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
		f.serveMultiDelete(w, r)
	case r.Method == http.MethodHead:
		f.serveHead(w, key)
	case r.Method == http.MethodGet && f.isList(r):
		f.serveList(w, r)
	case r.Method == http.MethodGet:
		f.mu.Lock()
		fail := f.getFail
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, ok := f.get(key)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3Store) serveMultiDelete(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	fail := f.deleteFail
	f.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var req struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}
	if err := xml.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result := struct {
		XMLName xml.Name `xml:"DeleteResult"`
		XMLNS   string   `xml:"xmlns,attr"`
		Deleted []struct {
			Key string `xml:"Key"`
		} `xml:"Deleted"`
	}{XMLNS: s3Namespace}
	f.mu.Lock()
	for _, object := range req.Objects {
		f.remove(object.Key)
		result.Deleted = append(result.Deleted, struct {
			Key string `xml:"Key"`
		}{Key: object.Key})
	}
	f.mu.Unlock()
	out, err := xml.Marshal(result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(out)
}

func (f *fakeS3Store) serveHead(w http.ResponseWriter, key string) {
	f.mu.Lock()
	body, ok := f.objects[key]
	bare := f.headBare
	length := f.headLen
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if bare {
		// Answer 200 without a Content-Length header. net/http would add one for a
		// handler that writes nothing, and the SDK binds HeadObject.ContentLength to that
		// header (s3/deserializers.go, awsRestxml_deserializeOpHttpBindingsHeadObjectOutput),
		// so a raw response is the only way to reach derefInt64's nil branch.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
		_ = buf.Flush()
		_ = conn.Close()
		return
	}
	size := int64(len(body))
	if length != nil {
		size = *length
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
}

// serveList answers both listing shapes the code uses: ListObjects (V1, the one COS is
// asked for, paged with a marker) and ListObjectsV2 (paged with a continuation token, which
// the AWS SDK's paginator drives). pageSize makes the V1 answer truncated, which is how a
// bucket with more snapshots than fit in one response behaves -- retention that ignored the
// marker would list the same first page forever and silently never prune.
func (f *fakeS3Store) serveList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	marker := r.URL.Query().Get("marker")
	f.mu.Lock()
	fail := f.listFail
	pageSize := f.pageSize
	if !r.URL.Query().Has("list-type") {
		f.markers = append(f.markers, marker)
	}
	var names []string
	for name := range f.objects {
		if strings.HasPrefix(name, prefix) && name > marker {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	sizes := make(map[string]int, len(names))
	for _, name := range names {
		sizes[name] = len(f.objects[name])
	}
	f.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	truncated := pageSize > 0 && len(names) > pageSize
	if truncated {
		names = names[:pageSize]
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="`)
	b.WriteString(s3Namespace)
	b.WriteString(`">`)
	for _, name := range names {
		b.WriteString("<Contents><Key>")
		_ = xml.EscapeText(&b, []byte(name))
		b.WriteString("</Key><Size>")
		b.WriteString(strconv.Itoa(sizes[name]))
		b.WriteString("</Size></Contents>")
	}
	if truncated {
		b.WriteString("<IsTruncated>true</IsTruncated><NextMarker>")
		_ = xml.EscapeText(&b, []byte(names[len(names)-1]))
		b.WriteString("</NextMarker>")
	} else {
		b.WriteString("<IsTruncated>false</IsTruncated>")
	}
	b.WriteString("</ListBucketResult>")
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, b.String())
}

// accessKeyOf pulls the access key id out of a SigV4 Authorization header, so a test can
// tell which credential was used to sign.
func accessKeyOf(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const marker = "Credential="
	i := strings.Index(auth, marker)
	if i < 0 {
		return ""
	}
	rest := auth[i+len(marker):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// listMarkers returns the marker each ListObjects V1 call carried, in order. Only the
// hand-rolled COS pagination uses it; the V2 pager uses a continuation token instead.
func (f *fakeS3Store) listMarkers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.markers...)
}

// s3TestEnv installs the credentials the AWS SDK needs to sign a request. Without them
// LoadDefaultConfig falls through to the EC2 instance metadata service -- a network call
// to 169.254.169.254 that no test here may depend on -- and every S3 test would either
// hang or fail for the wrong reason. AWS_MAX_ATTEMPTS keeps a fault-injection test from
// spending its budget on SDK retries.
func s3TestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_REGION", "test-region")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
}

func s3Target(f *fakeS3Store, keep int, key []byte) Target {
	return Target{
		Type:         TypeS3,
		HMACKey:      key,
		Bucket:       fakeBucket,
		Prefix:       fakePrefix,
		Endpoint:     f.endpoint(),
		Region:       "test-region",
		SnapshotBase: fakeBase,
		Keep:         keep,
		Timeout:      15 * time.Second,
	}
}

func cosTarget(f *fakeS3Store, keep int, key []byte) Target {
	t := s3Target(f, keep, key)
	t.Type = TypeCOS
	return t
}

func sftpTarget(addr, knownHostsFile, remoteDir string, keep int, key []byte) Target {
	return Target{
		Type:           TypeSFTP,
		HMACKey:        key,
		Host:           addr,
		Username:       "wecert",
		RemoteDir:      remoteDir,
		PasswordEnv:    "WECERT_EDGE_SFTP_PASSWORD",
		KnownHostsFile: knownHostsFile,
		SnapshotBase:   fakeBase,
		Keep:           keep,
		Timeout:        15 * time.Second,
	}
}

// snapshotName builds the object name the state package writes: <base>.backup-<stamp>.db.
func snapshotName(stamp string) string { return fakeBase + ".backup-" + stamp + ".db" }

func objectKey(stamp string) string { return fakePrefix + "/" + snapshotName(stamp) }

func writeSnapshot(t *testing.T, dir, name, body string) string {
	t.Helper()
	src := filepath.Join(dir, name)
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return src
}

// restoreLeftovers lists what an aborted restore left in the directory that receives the
// download. The "<temp>.remotekey" bookkeeping file is reported separately: downloadS3Object
// and downloadSFTPFile leave it behind when a restore is refused, and an assertion that the
// directory is empty would then fail on that wart rather than on the property under test --
// that the downloaded bytes do not stay in the directory a restore installs from.
func restoreLeftovers(t *testing.T, dir string) (bytesLeft, bookkeeping []string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".remotekey") {
			bookkeeping = append(bookkeeping, entry.Name())
			continue
		}
		bytesLeft = append(bytesLeft, entry.Name())
	}
	return bytesLeft, bookkeeping
}

// --- S3 and COS retention -------------------------------------------------------

// Retention must keep exactly Keep recovery points, must never count a ".hmac" sidecar
// as one of them, and must take a sidecar away with the snapshot it signs. A sidecar left
// behind is worse than clutter: it names a signature for an object that no longer exists,
// and retention that counts sidecars evicts real recovery points to make room for them.
func TestS3RetentionKeepsExactlyTheConfiguredNumberOfSnapshots(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	key := []byte("retention-signing-key")
	stamps := []string{"20260101T000000.000Z", "20260102T000000.000Z", "20260103T000000.000Z"}
	for i, stamp := range stamps {
		body := []byte(fmt.Sprintf("snapshot-%d", i+1))
		store.put(objectKey(stamp), body)
		store.put(objectKey(stamp)+".hmac", []byte(SignSnapshot(key, body)))
	}
	dir := t.TempDir()
	newest := "20260104T000000.000Z"
	src := writeSnapshot(t, dir, snapshotName(newest), "snapshot-4")

	if err := Upload(context.Background(), s3Target(store, 2, key), src); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	want := []string{
		objectKey("20260103T000000.000Z"),
		objectKey("20260103T000000.000Z") + ".hmac",
		objectKey(newest),
		objectKey(newest) + ".hmac",
	}
	if got := store.keys(); !equalStrings(got, want) {
		t.Fatalf("bucket after keep=2 upload = %v, want %v", got, want)
	}
	// The sidecar published for this snapshot must sign this snapshot's bytes: it is the
	// only proof a later restore has that the object came from this deployment.
	sidecar, ok := store.get(objectKey(newest) + ".hmac")
	if !ok {
		t.Fatalf("no sidecar published for %s", objectKey(newest))
	}
	if got, want := strings.TrimSpace(string(sidecar)), SignSnapshot(key, []byte("snapshot-4")); got != want {
		t.Fatalf("sidecar = %q, want %q", got, want)
	}
}

// Keep=1 with one signed pair already in the bucket is the boundary the upload path is
// most likely to get wrong, because a signed upload prunes twice (object, then sidecar).
// The older pair goes; the pair just published must survive it.
func TestS3RetentionKeepOneKeepsTheNewestSignedPair(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	key := []byte("retention-signing-key")
	older := []byte("older")
	store.put(objectKey("20260101T000000.000Z"), older)
	store.put(objectKey("20260101T000000.000Z")+".hmac", []byte(SignSnapshot(key, older)))
	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260102T000000.000Z"), "newest")

	if err := Upload(context.Background(), s3Target(store, 1, key), src); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	want := []string{objectKey("20260102T000000.000Z"), objectKey("20260102T000000.000Z") + ".hmac"}
	if got := store.keys(); !equalStrings(got, want) {
		t.Fatalf("bucket after keep=1 upload = %v, want the signed pair just published, %v", got, want)
	}
}

// A shared bucket holds other installations' snapshots under the same prefix. Retention
// must not delete them: one deployment's keep policy is not authority over another
// deployment's recovery points.
func TestS3RetentionIgnoresAnotherInstallationsSnapshots(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	foreign := fakePrefix + "/other.db.backup-20270101T000000.000Z.db"
	store.put(foreign, []byte("someone else's recovery point"))
	store.put(foreign+".hmac", []byte("their signature"))
	store.put(objectKey("20260101T000000.000Z"), []byte("our older snapshot"))
	store.put(objectKey("20260101T000000.000Z")+".hmac", []byte("our older signature"))

	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260102T000000.000Z"), "our newest snapshot")
	if err := Upload(context.Background(), s3Target(store, 1, nil), src); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if !store.has(foreign) || !store.has(foreign+".hmac") {
		t.Fatal("retention deleted another installation's snapshot from a shared prefix")
	}
	if store.has(objectKey("20260101T000000.000Z")) || store.has(objectKey("20260101T000000.000Z")+".hmac") {
		t.Fatal("retention kept our own expired snapshot")
	}
}

// Keep=0 means "this target keeps everything". Retention must not run at all: an
// operator who never set a keep value must not lose a snapshot to a default.
func TestS3RetentionIsSkippedWithoutKeep(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.put(objectKey("20260101T000000.000Z"), []byte("must survive"))
	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260102T000000.000Z"), "newest")

	if err := Upload(context.Background(), s3Target(store, 0, nil), src); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !store.has(objectKey("20260101T000000.000Z")) {
		t.Fatal("keep=0 deleted an existing snapshot")
	}
	if n := store.countRequests(http.MethodDelete); n != 0 {
		t.Fatalf("keep=0 issued %d DELETE requests, want 0", n)
	}
}

// COS is S3-compatible for object I/O but not for the multi-object delete payload: the
// AWS SDK does not add the Content-MD5 COS requires for it, so retention has to use
// single-object deletes there. It also answers ListObjectsV2 with NoSuchKey on some
// deployments, which is why the listing must be V1. Both are invisible until someone
// lowers keep on a COS target and the prune starts failing every backup.
func TestCOSRetentionDeletesObjectsOneByOneAndListsWithV1(t *testing.T) {
	s3TestEnv(t)
	t.Setenv("TENCENTCLOUD_SECRET_ID", "test-cos-id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "test-cos-key")
	store := newFakeS3Store(t)
	store.put(objectKey("20260101T000000.000Z"), []byte("one"))
	store.put(objectKey("20260101T000000.000Z")+".hmac", []byte("one-signature"))
	store.put(objectKey("20260102T000000.000Z"), []byte("two"))
	store.put(objectKey("20260102T000000.000Z")+".hmac", []byte("two-signature"))

	dir := t.TempDir()
	newest := "20260103T000000.000Z"
	src := writeSnapshot(t, dir, snapshotName(newest), "three")
	if err := Upload(context.Background(), cosTarget(store, 1, []byte("cos-signing-key")), src); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if got := store.countRequests(http.MethodPost); got != 0 {
		t.Fatalf("COS prune used %d multi-object deletes, want single-object deletes only", got)
	}
	// Two snapshots and their two sidecars.
	if got := store.countRequests(http.MethodDelete); got != 4 {
		t.Fatalf("COS prune issued %d DELETEs, want 4 (two pairs)", got)
	}
	want := []string{objectKey(newest), objectKey(newest) + ".hmac"}
	if got := store.keys(); !equalStrings(got, want) {
		t.Fatalf("COS bucket after keep=1 upload = %v, want %v", got, want)
	}
	for _, request := range store.requests() {
		if strings.Contains(request, "list-type=2") {
			t.Fatalf("COS listing used ListObjectsV2 (%s), which some deployments answer with NoSuchKey", request)
		}
	}
}

// --- which snapshot a restore may consider --------------------------------------

// A ".hmac" sidecar sorts after the object it signs, so a listing that does not filter
// sidecars reports the signature as the newest snapshot -- and a restore would install
// 64 bytes of hex as the state database.
func TestDownloadPicksTheSnapshotAndNeverItsSidecar(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	key := []byte("restore-signing-key")
	older := objectKey("20260101T000000.000Z")
	newest := objectKey("20260102T000000.000Z")
	store.put(older, []byte("older snapshot"))
	store.put(older+".hmac", []byte(SignSnapshot(key, []byte("older snapshot"))))
	store.put(newest, []byte("newest snapshot"))
	store.put(newest+".hmac", []byte(SignSnapshot(key, []byte("newest snapshot"))))

	dir := t.TempDir()
	restored, err := DownloadLatest(context.Background(), s3Target(store, 0, key), dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "newest snapshot" {
		t.Fatalf("restored %q, want the newest snapshot's bytes", got)
	}
}

// The snapshot base name is what keeps a restore from installing another installation's
// database, which would replace this host's private keys with someone else's. A bucket
// that holds only other names must report "nothing to restore", not pick the newest
// object it can see.
func TestDownloadReportsWhenOnlyAnotherInstallationsSnapshotsExist(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.put(fakePrefix+"/other.db.backup-20270101T000000.000Z.db", []byte("not ours"))
	dir := t.TempDir()

	_, err := DownloadLatest(context.Background(), s3Target(store, 0, nil), dir)
	if err == nil || !strings.Contains(err.Error(), "no snapshots found") {
		t.Fatalf("DownloadLatest error = %v, want no-snapshots-found", err)
	}
	if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
		t.Fatalf("failed restore left %v in the state directory", left)
	}
}

func TestDownloadReportsListingAndFetchFailures(t *testing.T) {
	cases := []struct {
		name    string
		fault   func(*fakeS3Store)
		env     [][2]string
		target  func(*fakeS3Store) Target
		dir     func(*testing.T) string
		wantSub string
	}{
		{
			name:    "listing fails",
			fault:   func(f *fakeS3Store) { f.listFail = true },
			target:  func(f *fakeS3Store) Target { return s3Target(f, 0, nil) },
			wantSub: "list remote snapshots",
		},
		{
			name:    "object fetch fails",
			fault:   func(f *fakeS3Store) { f.getFail = true },
			target:  func(f *fakeS3Store) Target { return s3Target(f, 0, nil) },
			wantSub: "download remote snapshot",
		},
		{
			name:    "COS credentials cannot be resolved",
			target:  func(f *fakeS3Store) Target { return cosTarget(f, 0, nil) },
			env:     [][2]string{{"TENCENTCLOUD_SECRET_ID", ""}, {"TENCENTCLOUD_SECRET_KEY", ""}},
			wantSub: "COS credentials require non-empty",
		},
		{
			name:    "download directory does not exist",
			target:  func(f *fakeS3Store) Target { return s3Target(f, 0, nil) },
			dir:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") },
			wantSub: "create restore temp file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s3TestEnv(t)
			for _, kv := range tc.env {
				t.Setenv(kv[0], kv[1])
			}
			store := newFakeS3Store(t)
			store.put(objectKey("20260101T000000.000Z"), []byte("snapshot"))
			if tc.fault != nil {
				tc.fault(store)
			}
			dir := t.TempDir()
			if tc.dir != nil {
				dir = tc.dir(t)
			}
			_, err := DownloadLatest(context.Background(), tc.target(store), dir)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("DownloadLatest error = %v, want it to mention %q", err, tc.wantSub)
			}
			if tc.dir == nil {
				if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
					t.Fatalf("failed restore left %v in the state directory", left)
				}
			}
		})
	}
}

// With no signing key configured there is no sidecar to check, and a restore must not
// invent one: fetching a missing ".hmac" would fail every restore for operators who
// never opted into signing.
func TestDownloadWithoutSigningKeyNeverReadsASidecar(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.put(objectKey("20260101T000000.000Z"), []byte("unsigned snapshot"))
	dir := t.TempDir()

	restored, err := DownloadLatest(context.Background(), s3Target(store, 0, nil), dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	for _, request := range store.requests() {
		if strings.HasPrefix(request, http.MethodGet+" ") && strings.Contains(request, ".hmac") {
			t.Fatalf("unsigned restore read %s", request)
		}
	}
}

// --- HMAC sidecar verification (S3) ---------------------------------------------

// A writable bucket is not a trusted restore source. When a signing key is configured,
// an object whose bytes do not match its sidecar must be refused -- and the refused
// download must not stay in the directory that the caller restores from.
func TestDownloadRefusesUnverifiableS3Snapshots(t *testing.T) {
	key := []byte("restore-signing-key")
	cases := []struct {
		name    string
		key     []byte
		sidecar func() (body string, present bool)
		wantSub string
	}{
		{
			name: "tampered object",
			key:  key,
			sidecar: func() (string, bool) {
				return SignSnapshot(key, []byte("the original bytes")), true
			},
			wantSub: "does not match",
		},
		{
			name: "missing sidecar",
			key:  key,
			sidecar: func() (string, bool) {
				return "", false
			},
			wantSub: "signature missing",
		},
		{
			name: "wrong signing key",
			key:  []byte("a-different-key"),
			sidecar: func() (string, bool) {
				return SignSnapshot(key, []byte("tampered bytes")), true
			},
			wantSub: "does not match",
		},
		{
			name: "sidecar is not a signature",
			key:  key,
			sidecar: func() (string, bool) {
				return "not-a-signature", true
			},
			wantSub: "not hex",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s3TestEnv(t)
			store := newFakeS3Store(t)
			remote := objectKey("20260101T000000.000Z")
			// The stored object is what the sidecar must not match; the title says why.
			store.put(remote, []byte("tampered bytes"))
			if body, ok := tc.sidecar(); ok {
				store.put(remote+".hmac", []byte(body))
			}
			dir := t.TempDir()
			_, err := DownloadLatest(context.Background(), s3Target(store, 0, tc.key), dir)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("DownloadLatest error = %v, want it to mention %q", err, tc.wantSub)
			}
			if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
				t.Fatalf("refused download left %v in the state directory", left)
			}
		})
	}
}

// --- SFTP restore and retention -------------------------------------------------

// The signed SFTP round trip is the only path that reads the sidecar over a second
// connection; it must both publish the sidecar and verify against the remote one.
func TestSFTPRestoreVerifiesTheSignatureSidecar(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	key := []byte("sftp-signing-key")
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "signed snapshot")

	// Keep=0: this test is about the signature chain, not retention.
	target := sftpTarget(addr, knownHosts, remoteDir, 0, key)
	if err := Upload(context.Background(), target, src); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(remoteDir, snapshotName("20260101T000000.000Z")+".hmac")); err != nil {
		t.Fatalf("signed upload published no sidecar: %v", err)
	}
	restored, err := DownloadLatest(context.Background(), target, dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "signed snapshot" {
		t.Fatalf("restored %q, want the published snapshot", got)
	}
}

// The SFTP sidecar is read by name from the remote directory, so every way it can fail
// to be there -- altered object, missing signature, signature from another deployment --
// must stop the restore instead of handing the caller unverified bytes.
func TestSFTPRestoreRefusesUnverifiableSnapshots(t *testing.T) {
	cases := []struct {
		name    string
		mangle  func(t *testing.T, remoteDir, stamp string)
		key     []byte
		wantSub string
	}{
		{
			name: "tampered snapshot",
			mangle: func(t *testing.T, remoteDir, stamp string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(remoteDir, snapshotName(stamp)), []byte("attacker bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantSub: "does not match",
		},
		{
			name: "missing sidecar",
			mangle: func(t *testing.T, remoteDir, stamp string) {
				t.Helper()
				if err := os.Remove(filepath.Join(remoteDir, snapshotName(stamp)+".hmac")); err != nil {
					t.Fatal(err)
				}
			},
			wantSub: "signature missing",
		},
		{
			name:    "wrong signing key",
			key:     []byte("a-different-key"),
			mangle:  func(*testing.T, string, string) {},
			wantSub: "does not match",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The local source snapshot lives in its own directory: the assertions below
			// are about what a restore leaves in the directory it downloads into, and a
			// source file sitting in it would be indistinguishable from a leftover.
			dir := t.TempDir()
			srcDir := t.TempDir()
			remoteDir := filepath.Join(t.TempDir(), "remote")
			addr, knownHosts, stop := startTestSFTP(t)
			defer stop()
			t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
			uploadKey := []byte("sftp-signing-key")
			stamp := "20260101T000000.000Z"
			src := writeSnapshot(t, srcDir, snapshotName(stamp), "signed snapshot")
			uploadTarget := sftpTarget(addr, knownHosts, remoteDir, 0, uploadKey)
			if err := Upload(context.Background(), uploadTarget, src); err != nil {
				t.Fatalf("Upload: %v", err)
			}
			tc.mangle(t, remoteDir, stamp)

			downloadKey := tc.key
			if downloadKey == nil {
				downloadKey = uploadKey
			}
			_, err := DownloadLatest(context.Background(), sftpTarget(addr, knownHosts, remoteDir, 0, downloadKey), dir)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("DownloadLatest error = %v, want it to mention %q", err, tc.wantSub)
			}
			if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
				t.Fatalf("refused download left %v in the state directory", left)
			}
		})
	}
}

// A key file is the credential most SFTP targets use, and it goes through a different
// branch than the password: read the file, parse it (with a passphrase when one is named)
// and offer the signer. A passphrase-protected key must work too -- it is the shape an
// operator is most likely to have, and a parser that only accepts plain keys turns a
// working target into a permanent backup failure.
func TestSFTPPrivateKeyAuthentication(t *testing.T) {
	cases := []struct {
		name       string
		passphrase string
	}{
		{name: "unencrypted key"},
		{name: "passphrase-protected key", passphrase: "correct horse battery staple"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			remoteDir := filepath.Join(t.TempDir(), "remote")
			addr, knownHosts, stop := startTestSFTPServer(t, serveTestSFTPRealFS)
			defer stop()

			target := sftpTarget(addr, knownHosts, remoteDir, 0, nil)
			target.PrivateKeyFile = writeTestPrivateKey(t, tc.passphrase)
			// The password variable is not configured at all: the key must be enough.
			target.PasswordEnv = "WECERT_EDGE_SFTP_PASSWORD"
			if tc.passphrase != "" {
				t.Setenv("WECERT_EDGE_SFTP_PASSPHRASE", tc.passphrase)
				target.PrivateKeyPassphraseEnv = "WECERT_EDGE_SFTP_PASSPHRASE"
			}

			stamp := "20260101T000000.000Z"
			src := writeSnapshot(t, dir, snapshotName(stamp), "signed snapshot")
			if err := Upload(context.Background(), target, src); err != nil {
				t.Fatalf("Upload with a private key: %v", err)
			}
			// The restore opens its own connection, so it exercises the same branch again.
			restored, err := DownloadLatest(context.Background(), target, dir)
			if err != nil {
				t.Fatalf("DownloadLatest with a private key: %v", err)
			}
			defer os.Remove(restored)
			got, err := os.ReadFile(restored)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "signed snapshot" {
				t.Fatalf("restored %q, want the uploaded snapshot", got)
			}
		})
	}
}

func writeTestPrivateKey(t *testing.T, passphrase string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, "wecert-test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "wecert-test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_wecert_test")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// "Newest" is decided by name across a directory that also holds sidecars, another
// installation's snapshots and whatever else an operator keeps there. Picking a
// directory entry or a signature would install garbage as the state database.
func TestSFTPDownloadIgnoresSidecarsDirectoriesAndForeignNames(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	ours := snapshotName("20260101T000000.000Z")
	if err := os.WriteFile(filepath.Join(remoteDir, ours), []byte("our snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A sidecar and a directory both sort after the snapshot they sit beside.
	if err := os.WriteFile(filepath.Join(remoteDir, ours+".hmac"), []byte("signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(remoteDir, snapshotName("20270101T000000.000Z")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteDir, "other.db.backup-20270101T000000.000Z.db"), []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}

	restored, err := DownloadLatest(context.Background(), sftpTarget(addr, knownHosts, remoteDir, 0, nil), dir)
	if err != nil {
		t.Fatalf("DownloadLatest: %v", err)
	}
	defer os.Remove(restored)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "our snapshot" {
		t.Fatalf("restored %q, want this installation's newest snapshot", got)
	}
}

// The SFTP counterpart of the S3 rule above: a remote directory that holds nothing of
// this installation's, or cannot be listed at all, must report that instead of picking up
// whatever it can see.
func TestSFTPDownloadReportsNothingToRestore(t *testing.T) {
	dir := t.TempDir()
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "other.db.backup-20270101T000000.000Z.db"), []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		remoteDir string
		wantSub   string
	}{
		{name: "no snapshots at all", remoteDir: empty, wantSub: "no SFTP snapshots in"},
		{name: "only another installation's snapshot", remoteDir: foreign, wantSub: "no SFTP snapshots in"},
		{name: "remote directory does not exist", remoteDir: filepath.Join(t.TempDir(), "absent"), wantSub: "list SFTP snapshots"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DownloadLatest(context.Background(), sftpTarget(addr, knownHosts, tc.remoteDir, 0, nil), dir)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("DownloadLatest error = %v, want it to mention %q", err, tc.wantSub)
			}
			if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
				t.Fatalf("failed restore left %v in the state directory", left)
			}
		})
	}
}

// Unsigned retention on SFTP: the oldest snapshot goes when the count exceeds Keep, and
// the names that are not snapshots -- sidecars, other installations' files -- do not
// count towards the limit.
func TestSFTPRetentionDeletesOldestUnsignedSnapshots(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	target := sftpTarget(addr, knownHosts, remoteDir, 2, nil)

	for _, stamp := range []string{"20260101T000000.000Z", "20260102T000000.000Z"} {
		src := writeSnapshot(t, dir, snapshotName(stamp), stamp)
		if err := Upload(context.Background(), target, src); err != nil {
			t.Fatalf("Upload %s: %v", stamp, err)
		}
	}
	newest := "20260103T000000.000Z"
	if err := Upload(context.Background(), target, writeSnapshot(t, dir, snapshotName(newest), newest)); err != nil {
		t.Fatalf("Upload %s: %v", newest, err)
	}

	entries, err := os.ReadDir(remoteDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	want := []string{snapshotName("20260102T000000.000Z"), snapshotName(newest)}
	if !equalStrings(names, want) {
		t.Fatalf("remote directory after keep=2 = %v, want %v", names, want)
	}
}

// Signed retention on a remote that does not hold a full set yet: the first signed
// snapshots must accumulate, because retention that runs before the limit is reached has
// nothing to reclaim. Signing is what makes this worth its own test: a signed upload
// prunes once for the object and once for the signature that follows it, and the second
// pass must not treat the snapshot it just published as an expired one.
func TestSFTPRetentionOnAGrowingSignedRemoteDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	key := []byte("sftp-retention-key")
	const keep = 3

	target := sftpTarget(addr, knownHosts, remoteDir, keep, key)
	stamps := []string{"20260101T000000.000Z", "20260102T000000.000Z"}
	for _, stamp := range stamps {
		if err := Upload(context.Background(), target, writeSnapshot(t, dir, snapshotName(stamp), stamp)); err != nil {
			t.Fatalf("Upload %s: %v", stamp, err)
		}
	}

	entries, err := os.ReadDir(remoteDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	var want []string
	for _, stamp := range stamps {
		want = append(want, snapshotName(stamp), snapshotName(stamp)+".hmac")
	}
	sort.Strings(want)
	if !equalStrings(names, want) {
		t.Fatalf("remote directory below keep=%d = %v, want every signed pair kept, %v", keep, names, want)
	}
}

// A retention failure happens *after* the snapshot is on the remote. The caller decides
// whether to still run VerifyUpload from IsUploaded, so the error must carry that
// distinction through whatever wrapping main.go adds; reporting it as a plain failure
// makes a healthy backup look red.
func TestSFTPPruneFailureStillCountsAsAnUploadedSnapshot(t *testing.T) {
	// One in-memory filesystem shared by every connection: the seed below is written
	// through a separate SSH session, and a per-connection filesystem would hide it from
	// the upload the test is about.
	files := sftp.InMemHandler()
	addr, knownHosts, stop := startTestSFTPServer(t, func(conn io.ReadWriteCloser) error {
		return serveInMemSFTP(conn, files)
	})
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	target := sftpTarget(addr, knownHosts, "/backup", 1, nil)

	// Seed an older snapshot through the same credentials the code under test uses.
	sess, err := openSFTP(context.Background(), target)
	if err != nil {
		t.Fatalf("openSFTP: %v", err)
	}
	if err := sess.client.MkdirAll(target.RemoteDir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	older := path.Join(target.RemoteDir, snapshotName("20260101T000000.000Z"))
	f, err := sess.client.Create(older)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write([]byte("older")); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close seed: %v", err)
	}
	sess.Close()

	dir := t.TempDir()
	newest := "20260102T000000.000Z"
	src := writeSnapshot(t, dir, snapshotName(newest), "newest")
	err = Upload(context.Background(), target, src)
	if err == nil {
		t.Fatal("a prune failure must be reported")
	}
	if !IsUploaded(err) {
		t.Fatalf("error %v does not report the snapshot as uploaded; main.go would skip VerifyUpload", err)
	}
	if !strings.Contains(err.Error(), "uploaded but retention prune failed") {
		t.Fatalf("error = %v, want it to say the upload itself succeeded", err)
	}
	if !strings.Contains(err.Error(), "prune SFTP snapshot") {
		t.Fatalf("error = %v, want the failing prune operation named", err)
	}
	// The point of IsUploaded: the object the error calls uploaded really is on the remote.
	check, err := openSFTP(context.Background(), target)
	if err != nil {
		t.Fatalf("openSFTP: %v", err)
	}
	defer check.Close()
	if _, err := check.client.Stat(path.Join(target.RemoteDir, snapshotName(newest))); err != nil {
		t.Fatalf("the error says the snapshot was uploaded but the remote does not have it: %v", err)
	}
}

// --- SFTP credentials and host key ----------------------------------------------

// Every unresolvable credential must stop the upload before anything is published, and
// the message must name what is missing: "connection failed" sends an operator to the
// firewall when the real problem is an unexported environment variable.
func TestSFTPCredentialsFailClosedBeforeDialing(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")

	badKey := filepath.Join(dir, "not-a-key")
	if err := os.WriteFile(badKey, []byte("this is not a private key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		target  func() Target
		env     [][2]string
		wantSub string
	}{
		{
			name: "password environment variable is empty",
			target: func() Target {
				return sftpTarget(addr, knownHosts, remoteDir, 0, nil)
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_PASSWORD", ""}},
			wantSub: `SFTP password environment variable "WECERT_EDGE_SFTP_PASSWORD" is empty`,
		},
		{
			name: "private key file cannot be read",
			target: func() Target {
				target := sftpTarget(addr, knownHosts, remoteDir, 0, nil)
				target.PrivateKeyFile = filepath.Join(dir, "absent-key")
				return target
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_PASSWORD", "password"}},
			wantSub: "read SFTP private key",
		},
		{
			name: "private key file is not a key",
			target: func() Target {
				target := sftpTarget(addr, knownHosts, remoteDir, 0, nil)
				target.PrivateKeyFile = badKey
				return target
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_PASSWORD", "password"}},
			wantSub: "parse SFTP private key",
		},
		{
			name: "passphrase is configured but the key is not encrypted",
			target: func() Target {
				target := sftpTarget(addr, knownHosts, remoteDir, 0, nil)
				target.PrivateKeyFile = badKey
				target.PrivateKeyPassphraseEnv = "WECERT_EDGE_SFTP_PASSPHRASE"
				return target
			},
			env: [][2]string{
				{"WECERT_EDGE_SFTP_PASSWORD", "password"},
				{"WECERT_EDGE_SFTP_PASSPHRASE", "passphrase"},
			},
			wantSub: "parse SFTP private key",
		},
		{
			name: "known_hosts file cannot be read",
			target: func() Target {
				return sftpTarget(addr, filepath.Join(dir, "absent-known-hosts"), remoteDir, 0, nil)
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_PASSWORD", "password"}},
			wantSub: "load SFTP known_hosts",
		},
		{
			name: "password variable is not configured at all",
			target: func() Target {
				target := sftpTarget(addr, knownHosts, remoteDir, 0, nil)
				target.PasswordEnv = "WECERT_EDGE_SFTP_UNSET_PASSWORD"
				return target
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_UNSET_PASSWORD", ""}},
			wantSub: "SFTP password environment variable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, kv := range tc.env {
				t.Setenv(kv[0], kv[1])
			}
			err := Upload(context.Background(), tc.target(), src)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Upload error = %v, want it to mention %q", err, tc.wantSub)
			}
			// Restore resolves the same credentials through its own code path: a target
			// that cannot authenticate must not upload *or* download.
			if _, err := DownloadLatest(context.Background(), tc.target(), t.TempDir()); err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("DownloadLatest error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// A host key that does not match known_hosts is the one machine-in-the-middle signal the
// client has. Connecting anyway would hand the snapshot keys to whoever answers on the
// host name.
func TestSFTPRejectsAnUnknownHostKey(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, _, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	// known_hosts holds a different host key than the server presents.
	impostor, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(impostor)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{addr}, signer.PublicKey())
	if err := os.WriteFile(knownHosts, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
	err = Upload(context.Background(), sftpTarget(addr, knownHosts, remoteDir, 0, nil), src)
	if err == nil || !strings.Contains(err.Error(), "connect SFTP") {
		t.Fatalf("Upload error = %v, want a host-key rejection", err)
	}
	if _, statErr := os.Stat(remoteDir); statErr == nil {
		t.Fatal("nothing may be written to a host whose key is not pinned")
	}
}

// A firewall that drops packets instead of refusing them leaves the TCP connection open
// and silent. Without a deadline on the connection the SSH handshake waits forever, and
// the backup goroutine -- and the daemon's shutdown drain -- waits with it.
func TestSFTPConnectTimeoutEndsASilentHandshake(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu       sync.Mutex
		accepted []net.Conn
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range accepted {
			_ = conn.Close()
		}
	})
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	target := sftpTarget(listener.Addr().String(), knownHosts, filepath.Join(dir, "remote"), 0, nil)
	target.Timeout = 250 * time.Millisecond
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")

	start := time.Now()
	err = Upload(context.Background(), target, src)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a server that never completes the handshake must not look like a successful upload")
	}
	if !strings.Contains(err.Error(), "connect SFTP") {
		t.Fatalf("Upload error = %v, want a connect failure", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("Upload took %s; the 250ms target timeout must end the handshake", elapsed)
	}
	// Restore opens the connection through its own code path; the deadline has to apply
	// there too, or a backup that fails fast is paired with a restore that never returns.
	start = time.Now()
	if _, err := DownloadLatest(context.Background(), target, dir); err == nil || !strings.Contains(err.Error(), "connect SFTP") {
		t.Fatalf("DownloadLatest error = %v, want a connect failure", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("DownloadLatest took %s; the 250ms target timeout must end the handshake", elapsed)
	}
}

// --- VerifyUpload ---------------------------------------------------------------

// VerifyUpload exists because a gateway can acknowledge a write that cannot be read back.
// A read-back that returns the wrong length is exactly that case, and it must fail rather
// than report a healthy backup.
func TestVerifyUploadReportsAS3SizeMismatch(t *testing.T) {
	cases := []struct {
		name    string
		fault   func(*fakeS3Store)
		wantSub string
	}{
		{
			name:    "gateway reports a truncated object",
			fault:   func(f *fakeS3Store) { f.headLen = ptr(int64(3)) },
			wantSub: "want 17",
		},
		{
			name:    "gateway reports no length at all",
			fault:   func(f *fakeS3Store) { f.headBare = true },
			wantSub: "size -1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s3TestEnv(t)
			store := newFakeS3Store(t)
			dir := t.TempDir()
			src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "seventeen bytes!!")
			// The object exists; only the length the gateway reports is wrong.
			store.put(objectKey("20260101T000000.000Z"), []byte("seventeen bytes!!"))
			tc.fault(store)
			err := VerifyUpload(context.Background(), s3Target(store, 0, nil), src)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("VerifyUpload error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// The SFTP read-back is the same guarantee over a different protocol: the size on the
// remote must equal the size of the file that was verified locally.
func TestVerifyUploadReportsAnSFTPSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(t.TempDir(), "remote")
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	target := sftpTarget(addr, knownHosts, remoteDir, 0, nil)
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "complete snapshot")

	if err := Upload(context.Background(), target, src); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := VerifyUpload(context.Background(), target, src); err != nil {
		t.Fatalf("VerifyUpload on a matching object: %v", err)
	}
	// A short write on the remote is the failure VerifyUpload is for.
	remote := filepath.Join(remoteDir, filepath.Base(src))
	if err := os.WriteFile(remote, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifyUpload(context.Background(), target, src)
	if err == nil || !strings.Contains(err.Error(), "size 5") {
		t.Fatalf("VerifyUpload error = %v, want a size mismatch", err)
	}
}

func TestVerifyUploadRejectsAMissingLocalSnapshot(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	err := VerifyUpload(context.Background(), s3Target(store, 0, nil), filepath.Join(t.TempDir(), "absent.db"))
	if err == nil || !strings.Contains(err.Error(), "stat uploaded snapshot") {
		t.Fatalf("VerifyUpload error = %v, want a stat failure", err)
	}
}

// --- target type, credentials, deadlines ----------------------------------------

// A typo in stateBackup.remoteTargets[].type must be reported, never ignored: silently
// skipping a target leaves an operator believing snapshots are off-host when they are not.
func TestUploadVerifyAndDownloadRejectAnUnknownTargetType(t *testing.T) {
	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
	unknown := Target{Type: "ftp", SnapshotBase: fakeBase}

	if err := Upload(context.Background(), unknown, src); err == nil || !strings.Contains(err.Error(), "unknown backup target type") {
		t.Fatalf("Upload error = %v, want unknown target type", err)
	}
	if err := VerifyUpload(context.Background(), unknown, src); err == nil || !strings.Contains(err.Error(), "unknown backup target type") {
		t.Fatalf("VerifyUpload error = %v, want unknown target type", err)
	}
	if _, err := DownloadLatest(context.Background(), unknown, dir); err == nil || !strings.Contains(err.Error(), "unknown backup target type") {
		t.Fatalf("DownloadLatest error = %v, want unknown target type", err)
	}
}

// Uploading a file that is not there is a failure the caller has to see. It must be a
// distinct message from a remote failure, or a mistyped snapshot path reads as a network
// problem -- and with a signing key the read happens before anything is uploaded.
func TestUploadReportsAMissingLocalSnapshot(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	absent := filepath.Join(t.TempDir(), "absent.db")

	if err := Upload(context.Background(), s3Target(store, 0, nil), absent); err == nil || !strings.Contains(err.Error(), "open snapshot") {
		t.Fatalf("Upload error = %v, want an open failure", err)
	}
	if err := Upload(context.Background(), s3Target(store, 0, []byte("key")), absent); err == nil || !strings.Contains(err.Error(), "read snapshot to sign") {
		t.Fatalf("signed Upload error = %v, want a read failure", err)
	}
	// The signing read happens before anything is sent, so a rejected target must surface
	// the target's error and not a signature one.
	signed := s3Target(store, 0, []byte("key"))
	signed.Type = "ftp"
	if err := Upload(context.Background(), signed, writeSnapshot(t, t.TempDir(), snapshotName("20260101T000000.000Z"), "snapshot")); err == nil || !strings.Contains(err.Error(), "unknown backup target type") {
		t.Fatalf("signed Upload error = %v, want the target type reported", err)
	}
}

// A signing key that cannot be used must fail the upload loudly. Publishing the object
// unsigned while the operator believes the bucket is signed is the exact lie the sidecar
// exists to prevent, so a sidecar that cannot be written locally aborts the upload.
func TestSignedUploadFailsWhenTheSidecarCannotBeWritten(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
	// A directory where the sidecar goes: WriteFile cannot replace it.
	if err := os.Mkdir(src+".hmac", 0o700); err != nil {
		t.Fatal(err)
	}

	err := Upload(context.Background(), s3Target(store, 0, []byte("signing-key")), src)
	if err == nil {
		t.Fatal("an upload whose signature could not be written must not report success")
	}
	if IsUploaded(err) {
		t.Fatalf("error %v claims a usable upload although no signature was published", err)
	}
}

// The request timeout is what keeps one unreachable target from stalling the backup loop
// (and the shutdown drain) indefinitely. A silently stalled endpoint must end at the
// configured deadline -- not at the five-minute default and not never.
func TestUploadStopsAtTheConfiguredTargetTimeout(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.stall = true
	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
	target := s3Target(store, 0, nil)
	target.Timeout = 250 * time.Millisecond

	start := time.Now()
	err := Upload(context.Background(), target, src)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a stalled endpoint must not look like a successful upload")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("Upload took %s; the 250ms target timeout must end the request", elapsed)
	}
}

// A cancelled context is how shutdown stops an in-flight restore. It must surface as an
// error rather than a zero-length file or a silent success.
func TestDownloadStopsAtACancelledContext(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.put(objectKey("20260101T000000.000Z"), []byte("snapshot"))
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DownloadLatest(ctx, s3Target(store, 0, nil), dir)
	if err == nil {
		t.Fatal("a cancelled context must not produce a successful restore")
	}
	if left, _ := restoreLeftovers(t, dir); len(left) != 0 {
		t.Fatalf("cancelled restore left %v in the state directory", left)
	}
}

// COS credentials come from the environment named by the target, and a missing one must
// fail before the upload rather than fall back to the AWS chain -- a COS endpoint that
// received AWS credentials would reject every request with an opaque signature error.
func TestCOSCredentialsComeFromTheConfiguredEnvironment(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")

	t.Setenv("TENCENTCLOUD_SECRET_ID", "")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "")
	err := Upload(context.Background(), cosTarget(store, 0, nil), src)
	if err == nil || !strings.Contains(err.Error(), "TENCENTCLOUD_SECRET_ID") {
		t.Fatalf("Upload error = %v, want the missing COS credential named", err)
	}

	// The AWS chain is not a substitute for a COS secret.
	if got := store.countRequests(http.MethodPut); got != 0 {
		t.Fatalf("COS uploaded with unresolvable credentials (%d PUTs)", got)
	}

	t.Setenv("WECERT_EDGE_COS_ID", "edge-cos-id")
	t.Setenv("WECERT_EDGE_COS_KEY", "edge-cos-key")
	target := cosTarget(store, 0, nil)
	target.SecretIDEnv = "WECERT_EDGE_COS_ID"
	target.SecretKeyEnv = "WECERT_EDGE_COS_KEY"
	if err := Upload(context.Background(), target, src); err != nil {
		t.Fatalf("Upload with named COS credentials: %v", err)
	}
	if keys := store.signedAccessKeys(); len(keys) == 0 || keys[len(keys)-1] != "edge-cos-id" {
		t.Fatalf("request was signed with %v, want the key from WECERT_EDGE_COS_ID", keys)
	}
}

// --- retention failures and listing shape ---------------------------------------

// A delete that the object store refuses is not a successful prune. Both protocols must
// report it, and both must report it as "uploaded": the snapshot itself is already there,
// and main.go only runs VerifyUpload when IsUploaded says so. Silence here is the worst
// outcome -- the operator would believe the bucket holds Keep snapshots while it grows
// without bound.
func TestRetentionReportsDeleteFailuresAsUploaded(t *testing.T) {
	cases := []struct {
		name   string
		target func(*fakeS3Store) Target
		env    [][2]string
	}{
		{
			name:   "S3 multi-object delete fails",
			target: func(f *fakeS3Store) Target { return s3Target(f, 1, nil) },
		},
		{
			name: "COS single-object delete fails",
			target: func(f *fakeS3Store) Target {
				return cosTarget(f, 1, nil)
			},
			env: [][2]string{
				{"TENCENTCLOUD_SECRET_ID", "test-cos-id"},
				{"TENCENTCLOUD_SECRET_KEY", "test-cos-key"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s3TestEnv(t)
			for _, kv := range tc.env {
				t.Setenv(kv[0], kv[1])
			}
			store := newFakeS3Store(t)
			store.put(objectKey("20260101T000000.000Z"), []byte("older"))
			store.put(objectKey("20260102T000000.000Z"), []byte("newer"))
			store.deleteFail = true
			dir := t.TempDir()
			newest := "20260103T000000.000Z"
			src := writeSnapshot(t, dir, snapshotName(newest), "newest")

			err := Upload(context.Background(), tc.target(store), src)
			if err == nil {
				t.Fatal("a refused delete must be reported")
			}
			if !IsUploaded(err) {
				t.Fatalf("error %v does not report the snapshot as uploaded", err)
			}
			if !strings.Contains(err.Error(), "prune remote snapshots") {
				t.Fatalf("error = %v, want the failing prune operation named", err)
			}
			// Nothing was deleted, so nothing may have been reported as reclaimed.
			for _, stamp := range []string{"20260101T000000.000Z", "20260102T000000.000Z"} {
				if !store.has(objectKey(stamp)) {
					t.Fatalf("a failed prune reported success for %s as well", stamp)
				}
			}
			if !store.has(objectKey(newest)) {
				t.Fatal("the snapshot the error calls uploaded is not in the bucket")
			}
		})
	}
}

// A listing that fails after the object landed is the same "uploaded but not pruned"
// story as a refused delete, and it is the shape a COS deployment produces when it
// answers the listing with an error instead of an empty result.
func TestCOSRetentionReportsAListingFailureAsUploaded(t *testing.T) {
	s3TestEnv(t)
	t.Setenv("TENCENTCLOUD_SECRET_ID", "test-cos-id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "test-cos-key")
	store := newFakeS3Store(t)
	store.listFail = true
	dir := t.TempDir()
	stamp := "20260101T000000.000Z"
	src := writeSnapshot(t, dir, snapshotName(stamp), "snapshot")

	err := Upload(context.Background(), cosTarget(store, 1, nil), src)
	if err == nil {
		t.Fatal("a listing failure during retention must be reported")
	}
	if !IsUploaded(err) {
		t.Fatalf("error %v does not report the snapshot as uploaded", err)
	}
	if !strings.Contains(err.Error(), "list remote snapshots") {
		t.Fatalf("error = %v, want the failing listing named", err)
	}
	if !store.has(objectKey(stamp)) {
		t.Fatal("the snapshot the error calls uploaded is not in the bucket")
	}
}

// The COS listing is hand-paged with a marker, because some COS deployments answer
// ListObjectsV2 with NoSuchKey. If the marker were ignored or the loop stopped after the
// first page, retention would see only the newest page and quietly stop pruning.
func TestCOSRetentionFollowsListingMarkers(t *testing.T) {
	s3TestEnv(t)
	t.Setenv("TENCENTCLOUD_SECRET_ID", "test-cos-id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "test-cos-key")
	store := newFakeS3Store(t)
	stamps := []string{
		"20260101T000000.000Z", "20260102T000000.000Z", "20260103T000000.000Z", "20260104T000000.000Z",
	}
	for _, stamp := range stamps {
		store.put(objectKey(stamp), []byte(stamp))
		store.put(objectKey(stamp)+".hmac", []byte("signature"))
	}
	// One key per page: four pre-existing snapshots arrive as four responses.
	store.pageSize = 1

	dir := t.TempDir()
	newest := "20260105T000000.000Z"
	src := writeSnapshot(t, dir, snapshotName(newest), "newest")
	// Signed, so the prune runs twice (object, then sidecar) and both passes have to page
	// through the same listing.
	if err := Upload(context.Background(), cosTarget(store, 2, []byte("cos-listing-key")), src); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	want := []string{
		objectKey("20260104T000000.000Z"),
		objectKey("20260104T000000.000Z") + ".hmac",
		objectKey(newest),
		objectKey(newest) + ".hmac",
	}
	if got := store.keys(); !equalStrings(got, want) {
		t.Fatalf("COS bucket after keep=2 with paged listings = %v, want %v", got, want)
	}
	markers := store.listMarkers()
	var withMarker int
	for _, marker := range markers {
		if marker != "" {
			withMarker++
		}
	}
	if withMarker == 0 {
		t.Fatalf("no listing carried a marker (%v): the page loop never followed the listing", markers)
	}
}

// --- VerifyUpload error paths ---------------------------------------------------

// VerifyUpload is the read-back proof. Every way the read-back can fail has to be an
// error: a target that cannot be reached, an object that is not there, an unreadable
// key. A silent pass turns "the gateway acknowledged the write" into "the backup is
// recoverable", which is the one claim verification exists to make.
func TestVerifyUploadReportsUnreadableTargets(t *testing.T) {
	cases := []struct {
		name    string
		target  func(*fakeS3Store, string) Target
		env     [][2]string
		prepare func(*fakeS3Store)
		wantSub string
	}{
		{
			name: "object is not in the bucket",
			target: func(f *fakeS3Store, _ string) Target {
				return s3Target(f, 0, nil)
			},
			wantSub: "read back s3://bucket/",
		},
		{
			name: "COS credentials cannot be resolved",
			target: func(f *fakeS3Store, _ string) Target {
				return cosTarget(f, 0, nil)
			},
			env:     [][2]string{{"TENCENTCLOUD_SECRET_ID", ""}, {"TENCENTCLOUD_SECRET_KEY", ""}},
			wantSub: "COS credentials require non-empty",
		},
		{
			name: "object is not on the SFTP remote",
			target: func(_ *fakeS3Store, addr string) Target {
				return Target{Type: TypeSFTP, Host: addr, Username: "wecert", RemoteDir: "/absent", PasswordEnv: "WECERT_EDGE_SFTP_PASSWORD", Timeout: 15 * time.Second}
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_PASSWORD", "password"}},
			wantSub: "read back SFTP snapshot",
		},
		{
			name: "SFTP password cannot be resolved",
			target: func(_ *fakeS3Store, addr string) Target {
				return Target{Type: TypeSFTP, Host: addr, Username: "wecert", RemoteDir: "/backup", PasswordEnv: "WECERT_EDGE_SFTP_PASSWORD", Timeout: 15 * time.Second}
			},
			env:     [][2]string{{"WECERT_EDGE_SFTP_PASSWORD", ""}},
			wantSub: "SFTP password environment variable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s3TestEnv(t)
			for _, kv := range tc.env {
				t.Setenv(kv[0], kv[1])
			}
			store := newFakeS3Store(t)
			if tc.prepare != nil {
				tc.prepare(store)
			}
			addr, knownHosts, stop := startTestSFTP(t)
			defer stop()
			dir := t.TempDir()
			src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
			target := tc.target(store, addr)
			target.KnownHostsFile = knownHosts
			target.SnapshotBase = fakeBase

			err := VerifyUpload(context.Background(), target, src)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("VerifyUpload error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// --- SFTP upload failures -------------------------------------------------------

// A remote directory that is not a directory, a local snapshot that is not there and a
// publish that cannot be completed must each be named. They are the failures an operator
// can fix, and "upload failed" alone sends them looking at the network instead.
func TestSFTPUploadReportsConfigurationFailures(t *testing.T) {
	dir := t.TempDir()
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	notADirectory := filepath.Join(dir, "remote-is-a-file")
	if err := os.WriteFile(notADirectory, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")

	cases := []struct {
		name    string
		target  Target
		src     string
		wantSub string
	}{
		{
			name:    "remoteDir is a file",
			target:  sftpTarget(addr, knownHosts, notADirectory, 0, nil),
			src:     src,
			wantSub: "create SFTP backup directory",
		},
		{
			name:    "local snapshot does not exist",
			target:  sftpTarget(addr, knownHosts, filepath.Join(dir, "remote"), 0, nil),
			src:     filepath.Join(dir, "absent.db"),
			wantSub: "open snapshot",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Upload(context.Background(), tc.target, tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Upload error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// A publish that fails must not be reported as an upload: the temporary file is not a
// snapshot, and a restore listing the directory would have to know the difference.
func TestSFTPUploadReportsAFailedPublish(t *testing.T) {
	files := sftp.InMemHandler()
	addr, knownHosts, stop := startTestSFTPServer(t, func(conn io.ReadWriteCloser) error {
		return serveInMemSFTP(conn, files)
	})
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")
	target := sftpTarget(addr, knownHosts, "/backup", 0, nil)

	// A directory already occupies the published name, so the rename cannot complete.
	sess, err := openSFTP(context.Background(), target)
	if err != nil {
		t.Fatalf("openSFTP: %v", err)
	}
	if err := sess.client.MkdirAll(path.Join(target.RemoteDir, snapshotName("20260101T000000.000Z"))); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	sess.Close()

	dir := t.TempDir()
	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
	err = Upload(context.Background(), target, src)
	if err == nil || !strings.Contains(err.Error(), "publish SFTP snapshot") {
		t.Fatalf("Upload error = %v, want a publish failure", err)
	}
	if IsUploaded(err) {
		t.Fatalf("error %v claims the snapshot was uploaded although the rename failed", err)
	}
}

// An SFTP host that refuses the connection is a different failure from a hung one, and it
// must come back as an error that names the host rather than as a generic failure.
func TestSFTPUploadReportsARefusedConnection(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := listener.Addr().String()
	_ = listener.Close() // nothing is listening on that port any more

	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{host}, signer.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	src := writeSnapshot(t, dir, snapshotName("20260101T000000.000Z"), "snapshot")
	target := sftpTarget(host, knownHosts, filepath.Join(dir, "remote"), 0, nil)
	target.Timeout = 5 * time.Second
	err = Upload(context.Background(), target, src)
	if err == nil || !strings.Contains(err.Error(), "connect SFTP") {
		t.Fatalf("Upload error = %v, want a connect failure naming the host", err)
	}
	// A restore dials through its own copy of the same code; a refused connection must
	// stop it there rather than being reported as "no snapshots".
	if _, err := DownloadLatest(context.Background(), target, dir); err == nil || !strings.Contains(err.Error(), "connect SFTP") {
		t.Fatalf("DownloadLatest error = %v, want a connect failure naming the host", err)
	}
}

// --- the contract the caller uses to decide whether to retry ---------------------
// main.go branches on IsUploaded to decide whether to still run VerifyUpload. Only the
// "the object landed, retention did not" marker may match -- treating a real upload
// failure as uploaded would report a healthy backup for an object that is not there.
func TestIsUploadedOnlyMatchesTheUploadedButPruneFailedMarker(t *testing.T) {
	pruneErr := errUploadedPruneFailed{errors.New("AccessDenied")}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"plain upload failure", fmt.Errorf("upload s3://bucket/key: %w", errors.New("connection reset")), false},
		{"signature read failure", fmt.Errorf("read snapshot to sign: %w", os.ErrNotExist), false},
		{"prune failure", pruneErr, true},
		{"wrapped prune failure", fmt.Errorf("remote target primary prune: %w", pruneErr), true},
		{"joined with a plain failure", errors.Join(errors.New("snapshot failed"), pruneErr), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUploaded(tc.err); got != tc.want {
				t.Fatalf("IsUploaded(%v) = %v, want %v", tc.err, got, tc.want)
			}
			if tc.err == nil {
				return
			}
			var marker errUploadedPruneFailed
			if errors.As(tc.err, &marker) != tc.want {
				t.Fatalf("errors.As(%v) = %v, want %v", tc.err, !tc.want, tc.want)
			}
		})
	}

	// The message is what an operator reads in the log; it has to say which half failed.
	if got, want := pruneErr.Error(), "uploaded but retention prune failed: AccessDenied"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(pruneErr, pruneErr.Unwrap()) {
		t.Fatal("Unwrap must expose the prune cause so the caller keeps errors.Is/As")
	}
}

// The end-to-end version of the same contract: the PUT succeeds, the listing that
// retention needs does not. The object is in the bucket and the caller must be told so.
func TestS3PruneFailureIsReportedAsAnUploadedObject(t *testing.T) {
	s3TestEnv(t)
	store := newFakeS3Store(t)
	store.listFail = true
	dir := t.TempDir()
	stamp := "20260101T000000.000Z"
	src := writeSnapshot(t, dir, snapshotName(stamp), "snapshot")

	err := Upload(context.Background(), s3Target(store, 1, nil), src)
	if err == nil {
		t.Fatal("a prune failure must be reported")
	}
	if !IsUploaded(err) {
		t.Fatalf("error %v does not report the object as uploaded", err)
	}
	if !strings.Contains(err.Error(), "uploaded but retention prune failed") {
		t.Fatalf("error = %v, want it to say the upload itself succeeded", err)
	}
	if !store.has(objectKey(stamp)) {
		t.Fatal("the object the error calls uploaded is not in the bucket")
	}
}

// --- helpers --------------------------------------------------------------------

// startTestSFTPServer is startTestSFTP with the SFTP subsystem supplied by the caller.
// The harness in remote_test.go serves the real filesystem, which is what most tests
// want; the retention-failure test needs a server whose Remove fails, and "the snapshot
// is on the remote but retention could not run" cannot be produced by a filesystem that
// always behaves. The SSH plumbing (host key, pinned known_hosts, password auth) is the
// same so that a test only varies the part it is about.
func startTestSFTPServer(t *testing.T, serve func(io.ReadWriteCloser) error) (addr, knownHostsPath string, stop func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPath = filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
		// Any key is accepted: the client's job is to present one, and the code under test
		// never inspects which key the server chose to trust.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSFTPSubsystem(raw, serverConfig, serve)
		}
	}()
	return listener.Addr().String(), knownHostsPath, func() {
		_ = listener.Close()
		<-done
	}
}

func serveTestSFTPSubsystem(raw net.Conn, config *ssh.ServerConfig, serve func(io.ReadWriteCloser) error) {
	_, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		conn, requests, err := channel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			for request := range requests {
				if request.Type != "subsystem" || string(request.Payload[4:]) != "sftp" {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				_ = serve(conn)
				return
			}
		}()
	}
}

// serveTestSFTPRealFS is the subsystem the stock harness in remote_test.go serves: the
// real filesystem. It exists separately here because startTestSFTPServer needs a function
// rather than a constructor.
func serveTestSFTPRealFS(conn io.ReadWriteCloser) error {
	server, err := sftp.NewServer(conn)
	if err != nil {
		return err
	}
	defer server.Close() // the caller closes the connection first
	return server.Serve()
}

// serveInMemSFTP serves an in-memory filesystem whose Remove always fails: an object
// store that accepted the write and then refused the delete. Every other operation is
// the stock in-memory handler, so the upload itself succeeds exactly as it would against
// a healthy server. The handler is passed in rather than created here so that several
// connections observe the same filesystem.
func serveInMemSFTP(conn io.ReadWriteCloser, inner sftp.Handlers) error {
	server := sftp.NewRequestServer(conn, sftp.Handlers{
		FileGet:  inner.FileGet,
		FilePut:  inner.FilePut,
		FileList: inner.FileList,
		FileCmd:  failRemoveCommander{inner: inner.FileCmd},
	})
	defer server.Close() // the caller closes the connection; a second close is not interesting
	return server.Serve()
}

// failRemoveCommander answers every file command but Remove, which is the one operation
// the retention work depends on.
type failRemoveCommander struct {
	inner sftp.FileCmder
}

func (c failRemoveCommander) Filecmd(r *sftp.Request) error {
	if r.Method == "Remove" {
		return errors.New("simulated server-side remove failure")
	}
	return c.inner.Filecmd(r)
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
