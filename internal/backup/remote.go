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
	switch target.Type {
	case TypeS3, TypeCOS:
		return downloadS3(ctx, target, dir)
	case TypeSFTP:
		return downloadSFTP(ctx, target, dir)
	default:
		return "", fmt.Errorf("unknown backup target type %q", target.Type)
	}
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
		if !e.IsDir() && strings.HasPrefix(e.Name(), t.SnapshotBase+".backup-") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no SFTP snapshots in %s", t.RemoteDir)
	}
	sort.Strings(names)
	in, err := session.client.Open(path.Join(t.RemoteDir, names[len(names)-1]))
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
	// Snapshot names sort chronologically, and only this deployment's base name is uploaded by one target.
	if len(objects) <= t.Keep {
		return nil
	}
	var victims []types.ObjectIdentifier
	for _, object := range objects[:len(objects)-t.Keep] {
		victims = append(victims, types.ObjectIdentifier{Key: object.Key})
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

func pruneSFTP(client *sftp.Client, t Target, current string) error {
	entries, err := client.ReadDir(t.RemoteDir)
	if err != nil {
		return fmt.Errorf("list SFTP snapshots: %w", err)
	}
	base := strings.Split(current, ".backup-")[0] + ".backup-"
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != current && strings.HasPrefix(entry.Name(), base) {
			names = append(names, entry.Name())
		}
	}
	if len(names) < t.Keep {
		return nil
	}
	sort.Strings(names)
	for _, name := range names[:len(names)-(t.Keep-1)] {
		if err := client.Remove(path.Join(t.RemoteDir, name)); err != nil {
			return fmt.Errorf("prune SFTP snapshot %s: %w", name, err)
		}
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
