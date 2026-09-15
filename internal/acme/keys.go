package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/atom/wecert/internal/config"
)

// GenerateKey 按配置生成证书私钥。默认 ECDSA P-256。
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case config.KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case config.KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case config.KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case config.KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

// MarshalPrivateKeyPEM 统一用 PKCS#8，避免 EC/RSA 各写一套。
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM 解析 PKCS#8 / PKCS#1 / SEC1 三种私钥编码。
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key of type %T is not a crypto.Signer", key)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unrecognized private key encoding (tried PKCS#8, PKCS#1, SEC1)")
}

// CreateCSRDER 构造证书签名请求，返回 DER 编码。
//
// 为什么是 DER 而不是 PEM：lego 的 api.OrderService.UpdateForCSR 会
// **自己**对传入的字节做 base64url 编码再塞进 ACME 的 csr 字段。
// 如果这里给 PEM，LE 收到的是 base64url(PEM 文本)，解出来再按 DER 解析
// 就会报 "asn1: structure error: tags don't match ... certificateRequest"。
//
// Subject 留空是有意的：classic profile 会把第一个 dNSName 提升为 CN，
// tlsserver profile 则完全不带 CN。交给 CA 决定即可。
func CreateCSRDER(key crypto.Signer, domains []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{},
		DNSNames: domains,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return der, nil
}

// ParseLeaf 解析 fullchain 里的第一张证书（叶子）。
func ParseLeaf(fullchainPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(fullchainPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// VerifyCoverage 确认签回来的证书确实覆盖了我们申请的全部域名。
//
// 这是部署前的最后一道闸门：不加这一步，一个不完整的订单结果
// 会被直接推到 CLB 上，把线上打挂。
func VerifyCoverage(leaf *x509.Certificate, want []string) error {
	have := make(map[string]bool, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		have[strings.ToLower(n)] = true
	}
	var missing []string
	for _, n := range want {
		if !have[strings.ToLower(n)] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("签回的证书未覆盖以下域名: %v (证书实际包含 %v)", missing, leaf.DNSNames)
	}
	return nil
}
