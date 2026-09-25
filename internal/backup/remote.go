// Package backup delivers already-consistent state snapshots to remote storage.
package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	TypeS3   = "s3"
	TypeCOS  = "cos"
	TypeSFTP = "sftp"
)

// Target contains no secret value. S3/COS use the AWS credential chain; SFTP
// reads a password from PasswordEnv or a private key from PrivateKeyFile.
type Target struct {
	// HMACKey, when non-empty, makes Upload write a <object>.hmac sidecar and
	// DownloadLatest refuse an object whose sidecar is missing or does not match.
	// It is NOT the state-encryption master key.
	HMACKey                                                                                         []byte
	Type, Name, Bucket, Prefix, Endpoint, Region                                                    string
	Host, Username, RemoteDir, PasswordEnv, PrivateKeyFile, PrivateKeyPassphraseEnv, KnownHostsFile string
	SecretIDEnv, SecretKeyEnv                                                                       string
	// SnapshotBase identifies this installation's database filename. It prevents a
	// restore from selecting another installation's backup in a shared target.
	SnapshotBase string
	Keep         int
	Timeout      time.Duration
}

// Upload sends src under its base name. S3 PutObject is all-or-nothing; SFTP
// writes a sibling temporary name and renames it only after Close succeeds.
func Upload(ctx context.Context, target Target, src string) error {
	return uploadWithSignature(ctx, target, src)
}

// uploadWithSignature is Upload plus the optional HMAC sidecar. The sidecar is the
// only thing that later proves "this object came from us" -- without it a writable
// backup prefix is a restore source for an attacker.
func uploadWithSignature(ctx context.Context, target Target, src string) error {
	if len(target.HMACKey) == 0 {
		return uploadOnce(ctx, target, src)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read snapshot to sign: %w", err)
	}
	sig := SignSnapshot(target.HMACKey, data)
	if err := uploadOnce(ctx, target, src); err != nil {
		return err
	}
	tmp := src + ".hmac"
	if err := os.WriteFile(tmp, []byte(sig+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	return uploadOnce(ctx, target, tmp)
}

func uploadOnce(ctx context.Context, target Target, src string) error {
	if target.Timeout <= 0 {
		target.Timeout = 5 * time.Minute
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, target.Timeout)
	defer cancel()
	switch target.Type {
	case TypeS3, TypeCOS:
		return uploadS3(ctx, target, src)
	case TypeSFTP:
		return uploadSFTP(ctx, target, src)
	default:
		return fmt.Errorf("unknown backup target type %q", target.Type)
	}
}

// VerifyUpload proves that the object just published is visible from a fresh
// remote operation and has the same length as the local, SQLite-verified
// snapshot.  PutObject/rename acknowledgement alone is not a recovery
// guarantee: a misconfigured gateway can acknowledge a write that cannot be
// read by the credentials used for recovery.  This deliberately checks the
// exact name, rather than "latest", so a concurrent retention pass or another
// installation in the same bucket cannot make an old backup look healthy.
func VerifyUpload(ctx context.Context, target Target, src string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat uploaded snapshot: %w", err)
	}
	if target.Timeout <= 0 {
		target.Timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, target.Timeout)
	defer cancel()
	switch target.Type {
	case TypeS3, TypeCOS:
		client, err := objectClient(ctx, target)
		if err != nil {
			return err
		}
		key := path.Join(strings.Trim(target.Prefix, "/"), filepath.Base(src))
		head, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &target.Bucket, Key: &key})
		if err != nil {
			return fmt.Errorf("read back %s://%s/%s: %w", target.Type, target.Bucket, key, err)
		}
		if head.ContentLength == nil || *head.ContentLength != info.Size() {
			return fmt.Errorf("read back %s://%s/%s: size %d, want %d", target.Type, target.Bucket, key, derefInt64(head.ContentLength), info.Size())
		}
		return nil
	case TypeSFTP:
		session, err := openSFTP(ctx, target)
		if err != nil {
			return err
		}
		defer session.Close()
		remote := path.Join(target.RemoteDir, filepath.Base(src))
		got, err := session.client.Stat(remote)
		if err != nil {
			return fmt.Errorf("read back SFTP snapshot: %w", err)
		}
		if got.Size() != info.Size() {
			return fmt.Errorf("read back SFTP snapshot %s: size %d, want %d", remote, got.Size(), info.Size())
		}
		return nil
	default:
		return fmt.Errorf("unknown backup target type %q", target.Type)
	}
}

func derefInt64(v *int64) int64 {
	if v == nil {
		return -1
	}
	return *v
}

// DownloadLatest retrieves the newest snapshot for target into dir with 0600
// permissions. The caller owns removing the returned file after state.Restore
// has verified and staged it.
func DownloadLatest(ctx context.Context, target Target, dir string) (string, error) {
	if target.SnapshotBase == "" {
		return "", fmt.Errorf("remote restore requires a snapshot base name")
	}
	if target.Timeout <= 0 {
		target.Timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, target.Timeout)
	defer cancel()
	var (
		src string
		err error
	)
	switch target.Type {
	case TypeS3, TypeCOS:
		src, err = downloadS3(ctx, target, dir)
	case TypeSFTP:
		src, err = downloadSFTP(ctx, target, dir)
	default:
		return "", fmt.Errorf("unknown backup target type %q", target.Type)
	}
	if err != nil {
		return "", err
	}
	return src, nil
}

type sftpSession struct {
	client *sftp.Client
	conn   *ssh.Client
}

func (s *sftpSession) Close() { _ = s.client.Close(); _ = s.conn.Close() }

// openSFTP centralizes the credential and host-key checks shared by upload and restore.
func openSFTP(ctx context.Context, t Target) (*sftpSession, error) {
	callback, err := knownhosts.New(t.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("load SFTP known_hosts: %w", err)
	}
	var auth ssh.AuthMethod
	if t.PrivateKeyFile != "" {
		key, err := os.ReadFile(t.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read SFTP private key: %w", err)
		}
		var signer ssh.Signer
		if t.PrivateKeyPassphraseEnv != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(os.Getenv(t.PrivateKeyPassphraseEnv)))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return nil, fmt.Errorf("parse SFTP private key: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	} else {
		password := os.Getenv(t.PasswordEnv)
		if password == "" {
			return nil, fmt.Errorf("SFTP password environment variable %q is empty", t.PasswordEnv)
		}
		auth = ssh.Password(password)
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.Host)
	if err != nil {
		return nil, fmt.Errorf("connect SFTP %s: %w", t.Host, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	cc, channels, requests, err := ssh.NewClientConn(raw, t.Host, &ssh.ClientConfig{User: t.Username, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: callback})
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("connect SFTP %s: %w", t.Host, err)
	}
	_ = raw.SetDeadline(time.Time{})
	conn := ssh.NewClient(cc, channels, requests)
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("start SFTP: %w", err)
	}
	return &sftpSession{client: client, conn: conn}, nil
}

func downloadSFTP(ctx context.Context, t Target, dir string) (string, error) {
	src, err := downloadSFTPFile(ctx, t, dir)
	if err != nil {
		return "", err
	}
	if len(t.HMACKey) > 0 {
		if err := verifySFTPSignature(ctx, t, src); err != nil {
			_ = os.Remove(src)
			return "", err
		}
	}
	return src, nil
}

// verifySFTPSignature reads the remote .hmac sidecar and checks the downloaded snapshot against it.
//
// It opens a **second** SFTP connection, and that connection is bounded by the caller's context:
// DownloadLatest put target.Timeout on it. Dialing with context.Background() discarded that
// deadline -- openSFTP only calls SetDeadline when the context has one -- so a server that accepted
// TCP and then never sent its SSH banner held the restore open for ever. Only reachable with a
// signing key configured, which is the recommended shape.
//
// One budget for the whole restore, not one per phase: a download that consumes the timeout leaves
// the signature read nothing, and the restore then fails with "snapshot signature: connect SFTP ...
// i/o timeout" instead of hanging. That is the intended trade-off -- target.Timeout is the promise
// the caller made about how long a restore may take.
func verifySFTPSignature(ctx context.Context, t Target, src string) error {
	sess, err := openSFTP(ctx, t)
	if err != nil {
		return fmt.Errorf("snapshot signature: %w", err)
	}
	defer sess.Close()
	name := filepath.Base(src)
	// The remote sidecar is the snapshot's own name + .hmac; the local temp name
	// differs. Read the remote key left beside the download.
	keyBytes, err := os.ReadFile(src + ".remotekey")
	if err != nil {
		return fmt.Errorf("snapshot signature: %w", err)
	}
	remoteName := strings.TrimSpace(string(keyBytes))
	f, err := sess.client.Open(filepath.Join(t.RemoteDir, remoteName+".hmac"))
	if err != nil {
		return fmt.Errorf("snapshot signature missing (%s.hmac): %w", remoteName, err)
	}
	defer f.Close()
	sig, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	_ = name
	return VerifySnapshot(t.HMACKey, data, string(sig))
}

// uploadingSuffix marks an SFTP upload in flight: uploadSFTP writes this sibling and renames it
// only after Close succeeds.
//
// A leftover of this shape is not a snapshot, and both listings have to say so. It sorts AFTER the
// snapshot it was going to become, so treating it as one made a restore pick a half-written file
// over the last complete snapshot beside it (state.Restore then rejects it on integrity_check, and
// the operator gets a failed restore while a good snapshot sits in the same directory), and made
// retention count it against Keep -- evicting a real recovery point to keep the garbage.
const uploadingSuffix = ".uploading-"

func downloadSFTPFile(ctx context.Context, t Target, dir string) (string, error) {
	session, err := openSFTP(ctx, t)
	if err != nil {
		return "", err
	}
	defer session.Close()
	entries, err := session.client.ReadDir(t.RemoteDir)
	if err != nil {
		return "", fmt.Errorf("list SFTP snapshots: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), t.SnapshotBase+".backup-") &&
			!strings.HasSuffix(e.Name(), ".hmac") && !strings.Contains(e.Name(), uploadingSuffix) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no SFTP snapshots in %s", t.RemoteDir)
	}
	sort.Strings(names)
	remoteName := names[len(names)-1]
	in, err := session.client.Open(path.Join(t.RemoteDir, remoteName))
	if err != nil {
		return "", fmt.Errorf("open SFTP snapshot: %w", err)
	}
	defer in.Close()
	out, err := os.CreateTemp(dir, ".wecert-remote-restore-*")
	if err != nil {
		return "", err
	}
	name := out.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		return "", err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", fmt.Errorf("download SFTP snapshot: %w", err)
	}
	if err = out.Close(); err != nil {
		return "", err
	}
	// See downloadS3Object: the sidecar is named after the remote file.
	_ = os.WriteFile(name+".remotekey", []byte(remoteName), 0o600)
	ok = true
	return name, nil
}

func objectClient(ctx context.Context, t Target) (*s3.Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if t.Region != "" {
		opts = append(opts, awsconfig.WithRegion(t.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load object-store credentials: %w", err)
	}
	if t.Type == TypeCOS {
		idEnv, keyEnv := t.SecretIDEnv, t.SecretKeyEnv
		if idEnv == "" {
			idEnv = "TENCENTCLOUD_SECRET_ID"
		}
		if keyEnv == "" {
			keyEnv = "TENCENTCLOUD_SECRET_KEY"
		}
		id, key := os.Getenv(idEnv), os.Getenv(keyEnv)
		if id == "" || key == "" {
			return nil, fmt.Errorf("COS credentials require non-empty %s and %s", idEnv, keyEnv)
		}
		cfg.Credentials = credentials.NewStaticCredentialsProvider(id, key, "")
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if t.Endpoint != "" {
			o.BaseEndpoint = &t.Endpoint
		}
	}), nil
}

func downloadS3(ctx context.Context, t Target, dir string) (string, error) {
	src, err := downloadS3Object(ctx, t, dir)
	if err != nil {
		return "", err
	}
	if err := verifyAgainstSidecar(ctx, t, src); err != nil {
		_ = os.Remove(src)
		return "", err
	}
	return src, nil
}

// verifyAgainstSidecar checks the downloaded snapshot against its remote .hmac.
// Fail closed when a signing key is configured: a writable backup prefix is not a
// trusted restore source.
func verifyAgainstSidecar(ctx context.Context, t Target, src string) error {
	if len(t.HMACKey) == 0 {
		return nil
	}
	// The sidecar name is the remote object key + ".hmac"; downloadS3Object leaves
	// the remote key in a sidecar file src+".remotekey".
	keyBytes, err := os.ReadFile(src + ".remotekey")
	if err != nil {
		return fmt.Errorf("snapshot signature: %w", err)
	}
	remoteKey := strings.TrimSpace(string(keyBytes))
	sig, err := downloadS3Bytes(ctx, t, remoteKey+".hmac")
	if err != nil {
		return fmt.Errorf("snapshot signature missing or unreadable (%s.hmac): %w", remoteKey, err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read downloaded snapshot: %w", err)
	}
	return VerifySnapshot(t.HMACKey, data, string(sig))
}

func downloadS3Object(ctx context.Context, t Target, dir string) (string, error) {
	client, err := objectClient(ctx, t)
	if err != nil {
		return "", err
	}
	prefix := path.Join(strings.Trim(t.Prefix, "/"), t.SnapshotBase+".backup-")
	objects, err := listObjects(ctx, client, t, prefix)
	if err != nil {
		return "", fmt.Errorf("list remote snapshots: %w", err)
	}
	var newest *types.Object
	for i := range objects {
		o := &objects[i]
		// Sidecars are not snapshots. A ".hmac" sibling sorts after its object in
		// lexicographic order, so "newest" would otherwise always be the signature.
		if o.Key != nil && strings.HasSuffix(*o.Key, ".hmac") {
			continue
		}
		if newest == nil || (o.Key != nil && newest.Key != nil && *o.Key > *newest.Key) {
			newest = o
		}
	}
	if newest == nil || newest.Key == nil {
		return "", fmt.Errorf("no snapshots found in %s://%s/%s", t.Type, t.Bucket, prefix)
	}
	out, err := os.CreateTemp(dir, ".wecert-remote-restore-*")
	if err != nil {
		return "", fmt.Errorf("create restore temp file: %w", err)
	}
	name := out.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		return "", err
	}
	obj, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &t.Bucket, Key: newest.Key})
	if err != nil {
		_ = out.Close()
		return "", fmt.Errorf("download remote snapshot: %w", err)
	}
	_, copyErr := io.Copy(out, obj.Body)
	closeErr := obj.Body.Close()
	fileErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if fileErr != nil {
		return "", fileErr
	}
	// Remember which remote object this temp file came from: the .hmac sidecar is
	// named after the remote key, not the random local temp name.
	if newest.Key != nil {
		_ = os.WriteFile(name+".remotekey", []byte(*newest.Key), 0o600)
	}
	ok = true
	return name, nil
}

func uploadS3(ctx context.Context, t Target, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer f.Close()
	client, err := objectClient(ctx, t)
	if err != nil {
		return err
	}
	key := path.Join(strings.Trim(t.Prefix, "/"), filepath.Base(src))
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: &t.Bucket, Key: &key, Body: f,
		ServerSideEncryption: "AES256"})
	if err != nil {
		return fmt.Errorf("upload %s://%s/%s: %w", t.Type, t.Bucket, key, err)
	}
	if t.Keep > 0 {
		if err := pruneS3(ctx, client, t, key); err != nil {
			// The object is already on the remote: retention failing is not "the upload
			// failed". Returning an error here made the caller skip VerifyUpload and
			// report a red backup while a usable snapshot sat in the bucket.
			// Prune is reported in the returned error only after verify has a chance to
			// run -- see Upload's contract: (uploaded, pruneErr).
			return errUploadedPruneFailed{err}
		}
	}
	return nil
}

func pruneS3(ctx context.Context, client *s3.Client, t Target, current string) error {
	base := strings.Split(filepath.Base(current), ".backup-")[0]
	prefix := path.Join(strings.Trim(t.Prefix, "/"), base+".backup-")
	objects, err := listObjects(ctx, client, t, prefix)
	if err != nil {
		return fmt.Errorf("list remote snapshots: %w", err)
	}
	// Only real snapshots count against Keep. A ".hmac" sidecar is not a recovery
	// point: counting it made keep=1 with one snapshot + one sidecar delete the
	// snapshot and leave the signature orphaned.
	var snapshots []types.Object
	for _, object := range objects {
		if object.Key != nil && strings.HasSuffix(*object.Key, ".hmac") {
			continue
		}
		snapshots = append(snapshots, object)
	}
	// Snapshot names sort chronologically, and only this deployment's base name is uploaded by one target.
	if len(snapshots) <= t.Keep {
		return nil
	}
	var victims []types.ObjectIdentifier
	for _, object := range snapshots[:len(snapshots)-t.Keep] {
		victims = append(victims, types.ObjectIdentifier{Key: object.Key})
		// Drop the sidecar with its snapshot. Leaving it behind makes the prefix
		// look signed for an object that is gone, and a later restore that picks
		// a still-present sibling would see a stale signature name in listings.
		if object.Key != nil {
			sidecar := *object.Key + ".hmac"
			victims = append(victims, types.ObjectIdentifier{Key: &sidecar})
		}
	}
	if t.Type == TypeCOS {
		// COS requires Content-MD5 for the S3 multi-object delete payload. The AWS
		// SDK does not add it for this operation, while COS accepts ordinary single
		// object deletes without that header. Retention runs infrequently and has at
		// most Keep-1 victims, so prefer the portable operation over hand-rolling a
		// signed XML request.
		for _, victim := range victims {
			if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &t.Bucket, Key: victim.Key}); err != nil {
				return fmt.Errorf("prune remote snapshots: %w", err)
			}
		}
		return nil
	}
	_, err = client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &t.Bucket, Delete: &types.Delete{Objects: victims, Quiet: ptr(true)}})
	if err != nil {
		return fmt.Errorf("prune remote snapshots: %w", err)
	}
	return nil
}

// listObjects uses COS's broadly-supported ListObjects (V1) endpoint. COS is
// S3-compatible for object I/O but some deployments answer ListObjectsV2 with
// NoSuchKey, which otherwise makes both restore and retention fail after a
// successful upload.
func listObjects(ctx context.Context, client *s3.Client, t Target, prefix string) ([]types.Object, error) {
	var objects []types.Object
	if t.Type == TypeCOS {
		input := &s3.ListObjectsInput{Bucket: &t.Bucket, Prefix: &prefix}
		for {
			page, err := client.ListObjects(ctx, input)
			if err != nil {
				return nil, err
			}
			objects = append(objects, page.Contents...)
			if page.IsTruncated == nil || !*page.IsTruncated || page.NextMarker == nil {
				break
			}
			input.Marker = page.NextMarker
		}
		return objects, nil
	}
	pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &t.Bucket, Prefix: &prefix})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		objects = append(objects, page.Contents...)
	}
	return objects, nil
}

func ptr[T any](v T) *T { return &v }

func uploadSFTP(ctx context.Context, t Target, src string) error {
	callback, err := knownhosts.New(t.KnownHostsFile)
	if err != nil {
		return fmt.Errorf("load SFTP known_hosts: %w", err)
	}
	var auth ssh.AuthMethod
	if t.PrivateKeyFile != "" {
		key, err := os.ReadFile(t.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("read SFTP private key: %w", err)
		}
		var signer ssh.Signer
		if t.PrivateKeyPassphraseEnv != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(os.Getenv(t.PrivateKeyPassphraseEnv)))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return fmt.Errorf("parse SFTP private key: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	} else {
		password := os.Getenv(t.PasswordEnv)
		if password == "" {
			return fmt.Errorf("SFTP password environment variable %q is empty", t.PasswordEnv)
		}
		auth = ssh.Password(password)
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", t.Host)
	if err != nil {
		return fmt.Errorf("connect SFTP %s: %w", t.Host, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	cc, channels, requests, err := ssh.NewClientConn(raw, t.Host, &ssh.ClientConfig{User: t.Username, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: callback})
	if err != nil {
		_ = raw.Close()
		return fmt.Errorf("connect SFTP %s: %w", t.Host, err)
	}
	_ = raw.SetDeadline(time.Time{})
	conn := ssh.NewClient(cc, channels, requests)
	defer conn.Close()
	client, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("start SFTP: %w", err)
	}
	defer client.Close()
	if err := client.MkdirAll(t.RemoteDir); err != nil {
		return fmt.Errorf("create SFTP backup directory: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer in.Close()
	final := path.Join(t.RemoteDir, filepath.Base(src))
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("random SFTP temp name: %w", err)
	}
	temp := final + ".uploading-" + hex.EncodeToString(random)
	out, err := client.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open SFTP temporary object: %w", err)
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Close()
	} else {
		_ = out.Close()
	}
	if err != nil {
		_ = client.Remove(temp)
		return fmt.Errorf("write SFTP snapshot: %w", err)
	}
	if err := client.Rename(temp, final); err != nil {
		return fmt.Errorf("publish SFTP snapshot: %w", err)
	}
	if t.Keep > 0 {
		if err := pruneSFTP(client, t, filepath.Base(src)); err != nil {
			return errUploadedPruneFailed{err}
		}
	}
	return nil
}

// pruneSFTP keeps the newest t.Keep snapshots.
//
// current is the name just published, and it is a candidate like any other -- exactly as it is in
// pruneS3, which lists the object it just wrote too. Excluding it made the signed-upload path wrong,
// because that path uploads twice and prunes twice: the first pass publishes the snapshot, the
// second publishes its .hmac sidecar, and on that second pass "the file just published" is the
// sidecar's name, so the snapshot it belongs to looked like an old sibling. With keep: 1 that
// deleted the only recovery point (the remote ended up empty) and with keep: N it left N-1
// (the default 7 left 6). Counting every snapshot, including the newest, is idempotent for both
// passes.
func pruneSFTP(client *sftp.Client, t Target, current string) error {
	entries, err := client.ReadDir(t.RemoteDir)
	if err != nil {
		return fmt.Errorf("list SFTP snapshots: %w", err)
	}
	// base comes from current's own name rather than from t.SnapshotBase, because current is always
	// a name that was just published and therefore carries the prefix: on the signed path's second
	// pass it is the sidecar's name ("...db.hmac"), whose prefix is still the snapshot's. Do not
	// "simplify" this into the sidecar name without checking the split still lands in the same place.
	base := strings.Split(current, ".backup-")[0] + ".backup-"
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		// Sidecars are not recovery points and an in-flight upload is not a snapshot; neither may
		// occupy a Keep slot, and the second one would also be renamed away or left behind by a
		// crashed upload.
		if entry.IsDir() || strings.HasSuffix(name, ".hmac") || strings.Contains(name, uploadingSuffix) {
			continue
		}
		if strings.HasPrefix(name, base) {
			names = append(names, name)
		}
	}
	if len(names) <= t.Keep {
		return nil
	}
	sort.Strings(names)
	for _, name := range names[:len(names)-t.Keep] {
		if err := client.Remove(path.Join(t.RemoteDir, name)); err != nil {
			return fmt.Errorf("prune SFTP snapshot %s: %w", name, err)
		}
		// Sidecar goes with its snapshot; a missing one is fine (older uploads
		// were unsigned).
		_ = client.Remove(path.Join(t.RemoteDir, name+".hmac"))
	}
	return nil
}

// errUploadedPruneFailed marks "the object is on the remote but retention prune
// failed". Callers must still verify the upload; treating this as a failed Upload
// lies about the recovery posture.
type errUploadedPruneFailed struct{ err error }

func (e errUploadedPruneFailed) Error() string {
	return "uploaded but retention prune failed: " + e.err.Error()
}
func (e errUploadedPruneFailed) Unwrap() error { return e.err }

// IsUploaded reports whether the object landed even though the overall Upload
// returned an error (retention only).
func IsUploaded(err error) bool {
	var p errUploadedPruneFailed
	return errors.As(err, &p)
}

// downloadS3Bytes fetches one object body (used for the .hmac sidecar).
func downloadS3Bytes(ctx context.Context, t Target, key string) ([]byte, error) {
	client, err := objectClient(ctx, t)
	if err != nil {
		return nil, err
	}
	obj, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &t.Bucket, Key: &key})
	if err != nil {
		return nil, err
	}
	defer obj.Body.Close()
	return io.ReadAll(io.LimitReader(obj.Body, 4096))
}
