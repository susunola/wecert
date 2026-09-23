// Package backup delivers already-consistent state snapshots to remote storage.
package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	Keep                                                                                            int
	Timeout                                                                                         time.Duration
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

func uploadS3(ctx context.Context, t Target, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer f.Close()
	opts := []func(*awsconfig.LoadOptions) error{}
	if t.Region != "" {
		opts = append(opts, awsconfig.WithRegion(t.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("load object-store credentials: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if t.Endpoint != "" {
			o.BaseEndpoint = &t.Endpoint
		}
		// COS and most self-hosted S3 endpoints require path-style addressing.
		if t.Type == TypeCOS {
			o.UsePathStyle = true
		}
	})
	key := path.Join(strings.Trim(t.Prefix, "/"), filepath.Base(src))
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: &t.Bucket, Key: &key, Body: f,
		ServerSideEncryption: "AES256"})
	if err != nil {
		return fmt.Errorf("upload %s://%s/%s: %w", t.Type, t.Bucket, key, err)
	}
	if t.Keep > 0 {
		if err := pruneS3(ctx, client, t, key); err != nil {
			return err
		}
	}
	return nil
}

func pruneS3(ctx context.Context, client *s3.Client, t Target, current string) error {
	base := strings.Split(filepath.Base(current), ".backup-")[0]
	prefix := path.Join(strings.Trim(t.Prefix, "/"), base+".backup-")
	pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &t.Bucket, Prefix: &prefix})
	var objects []types.Object
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list remote snapshots: %w", err)
		}
		objects = append(objects, page.Contents...)
	}
	// Snapshot names sort chronologically, and only this deployment's base name is uploaded by one target.
	if len(objects) <= t.Keep {
		return nil
	}
	var victims []types.ObjectIdentifier
	for _, object := range objects[:len(objects)-t.Keep] {
		victims = append(victims, types.ObjectIdentifier{Key: object.Key})
	}
	_, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &t.Bucket, Delete: &types.Delete{Objects: victims, Quiet: ptr(true)}})
	if err != nil {
		return fmt.Errorf("prune remote snapshots: %w", err)
	}
	return nil
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
			return err
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
