// Package backup delivers already-consistent state snapshots to remote storage.
package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
	Type, Name, Bucket, Prefix, Endpoint, Region                           string
	Host, Username, RemoteDir, PasswordEnv, PrivateKeyFile, KnownHostsFile string
}

// Upload sends src under its base name. S3 PutObject is all-or-nothing; SFTP
// writes a sibling temporary name and renames it only after Close succeeds.
func Upload(ctx context.Context, target Target, src string) error {
	switch target.Type {
	case TypeS3, TypeCOS:
		return uploadS3(ctx, target, src)
	case TypeSFTP:
		return uploadSFTP(target, src)
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
	return nil
}

func uploadSFTP(t Target, src string) error {
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
		signer, err := ssh.ParsePrivateKey(key)
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
	conn, err := ssh.Dial("tcp", t.Host, &ssh.ClientConfig{User: t.Username, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: callback})
	if err != nil {
		return fmt.Errorf("connect SFTP %s: %w", t.Host, err)
	}
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
	temp := final + ".uploading"
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
	return nil
}
