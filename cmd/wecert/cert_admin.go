package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
)

// configPathForAdmin is the config file this daemon was started with. The web
// console writes desired-state changes back to it.
// openStateStore is the daemon's already-open state database, shared with the
// admin surface so it never fights the flock.
var openStateStore *state.Store

var configPathForAdmin string

// marshalRegistry always emits a JSON array. json.MarshalIndent(nil) is "null",
// and the next Unmarshal into a []map leaves the reader with a nil slice and a
// console that cannot show the registry until something else rewrites it.
func marshalRegistry(v []map[string]any) []byte {
	if v == nil {
		v = []map[string]any{}
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// registerCertAdminOps fills the certificate/account management seams the web
// console calls. Called from adminOps so the wiring lives in one place.
func registerCertAdminOps(ops *webhook.AdminOps, cfg *config.Config, log *slog.Logger) {
	ops.ListAccounts = func(ctx context.Context) (any, error) {
		return listCloudAccounts(cfg)
	}
	ops.AddAccount = func(ctx context.Context, body map[string]any) (any, error) {
		return addCloudAccount(cfg, body, log)
	}
	ops.RemoveAccount = func(ctx context.Context, uin string) (any, error) {
		return removeCloudAccount(cfg, uin, log)
	}
	ops.ListBindings = func(ctx context.Context) (any, error) {
		return listCloudBindings(cfg)
	}
	ops.CreateCertificate = func(ctx context.Context, body map[string]any) (any, error) {
		return createCertificateAdmin(cfg, body, log)
	}
	ops.DeleteCertificate = func(ctx context.Context, name string) (any, error) {
		return deleteCertificateAdmin(cfg, name, log)
	}
	ops.BindCertificate = func(ctx context.Context, name string, body map[string]any) (any, error) {
		return bindCertificateAdmin(cfg, name, body, log)
	}
	ops.UnbindCertificate = func(ctx context.Context, name string) (any, error) {
		return unbindCertificateAdmin(cfg, name, log)
	}
}

func cloudAccountsPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.StatePath), "cloud-accounts.json")
}

func listCloudAccounts(cfg *config.Config) (any, error) {
	type acct struct {
		Name string `json:"name"`
		UIN  string `json:"uin"`
		Cred string `json:"cred"`
	}
	out := []acct{}
	if cfg.Tencent.UIN != "" {
		out = append(out, acct{Name: "default", UIN: cfg.Tencent.UIN, Cred: cfg.Tencent.CredentialMode})
	}
	if b, err := os.ReadFile(cloudAccountsPath(cfg)); err == nil {
		var extra []acct
		if json.Unmarshal(b, &extra) == nil {
			seen := map[string]bool{}
			for _, a := range out {
				seen[a.UIN] = true
			}
			for _, a := range extra {
				if !seen[a.UIN] {
					out = append(out, a)
					seen[a.UIN] = true
				}
			}
		}
	}
	return map[string]any{"accounts": out}, nil
}

func addCloudAccount(cfg *config.Config, body map[string]any, log *slog.Logger) (any, error) {
	name, _ := body["name"].(string)
	uin, _ := body["uin"].(string)
	cred, _ := body["cred"].(string)
	cloud, _ := body["cloud"].(string)
	secretID, _ := body["secretId"].(string)
	secretKey, _ := body["secretKey"].(string)
	keyPath, _ := body["keyPath"].(string)
	if name == "" {
		name = "account-" + uin
	}
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(cfg.StatePath), "accounts", name+".key")
	}
	if cred == "static" && secretID != "" {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return nil, err
		}
		payload := "TENCENTCLOUD_SECRET_ID=" + secretID + "\nTENCENTCLOUD_SECRET_KEY=" + secretKey + "\n"
		if err := os.WriteFile(keyPath, []byte(payload), 0o600); err != nil {
			return nil, err
		}
		log.Info("wrote cloud account credentials", "path", keyPath, "uin", uin, "cloud", cloud)
	}
	if uin == "" {
		uin = "auto:" + name
	}
	regPath := cloudAccountsPath(cfg)
	var list []map[string]any
	if b, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(b, &list)
	}
	list = append(list, map[string]any{
		"name": name, "uin": uin, "cred": cred, "cloud": cloud, "keyPath": keyPath,
	})
	b := marshalRegistry(list)
	if err := os.WriteFile(regPath, b, 0o600); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "name": name, "uin": uin, "cloud": cloud, "keyPath": keyPath,
		"note": "AK/SK stored as 0600 on the daemon host; never echoed back"}, nil
}

func removeCloudAccount(cfg *config.Config, uin string, log *slog.Logger) (any, error) {
	regPath := cloudAccountsPath(cfg)
	var list []map[string]any
	b, err := os.ReadFile(regPath)
	if err != nil {
		return map[string]any{"ok": true, "removed": 0}, nil
	}
	_ = json.Unmarshal(b, &list)
	var kept []map[string]any
	removed := 0
	for _, a := range list {
		if fmt.Sprint(a["uin"]) == uin {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	out := marshalRegistry(kept)
	_ = os.WriteFile(regPath, out, 0o600)
	log.Info("removed cloud account", "uin", uin, "removed", removed)
	return map[string]any{"ok": true, "removed": removed}, nil
}

func listCloudBindings(cfg *config.Config) (any, error) {
	type listener struct {
		ID    string `json:"id"`
		Proto string `json:"proto"`
		Port  int    `json:"port"`
		SNI   string `json:"sni"`
	}
	type lb struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		Region    string     `json:"region"`
		Account   string     `json:"account"`
		Listeners []listener `json:"listeners"`
	}
	_ = lb{}
	return map[string]any{"bindings": []any{}}, nil
}

func createCertificateAdmin(cfg *config.Config, body map[string]any, log *slog.Logger) (any, error) {
	name, _ := body["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	domains := []string{}
	if raw, ok := body["domains"].([]any); ok {
		for _, d := range raw {
			domains = append(domains, fmt.Sprint(d))
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	profile := fmt.Sprint(body["profile"])
	if profile == "" || profile == "<nil>" {
		profile = "classic"
	}
	keyType := fmt.Sprint(body["keyType"])
	if keyType == "" || keyType == "<nil>" {
		keyType = "ecdsa-p256"
	}
	uin := ""
	if v, ok := body["uin"].(string); ok {
		uin = v
	}
	renewBefore := renewBeforeToGoDuration(fmt.Sprint(body["renewBefore"]))
	deploy, _ := body["deploy"].(string)
	dnsCfg, _ := body["dns"].(map[string]any)

	// DNS token / file → 0600 file + config wiring so DNS-01 can run.
	// cred=reused leaves the daemon's existing dns block untouched.
	if dnsCfg != nil {
		provider, _ := dnsCfg["provider"].(string)
		cred, _ := dnsCfg["cred"].(string)
		switch cred {
		case "reused", "":
			// keep whatever dns.* the daemon already has
		case "token":
			tok, _ := dnsCfg["token"].(string)
			if tok == "" {
				return nil, fmt.Errorf("dns.cred=token requires dns.token")
			}
			tokPath := filepath.Join(filepath.Dir(cfg.StatePath), "dns", name+".token")
			if err := os.MkdirAll(filepath.Dir(tokPath), 0o700); err != nil {
				return nil, fmt.Errorf("create dns credential dir: %w", err)
			}
			if err := os.WriteFile(tokPath, []byte(tok), 0o600); err != nil {
				return nil, fmt.Errorf("store DNS token: %w", err)
			}
			log.Info("stored DNS token", "cert", name, "path", tokPath)
			if err := wireDNSCredentials(configPathForAdmin, provider, tokPath); err != nil {
				log.Warn("could not wire DNS credentials", "err", err)
			}
		case "file":
			filePath, _ := dnsCfg["file"].(string)
			if filePath == "" {
				return nil, fmt.Errorf("dns.cred=file requires dns.file")
			}
			if err := wireDNSCredentials(configPathForAdmin, provider, filePath); err != nil {
				log.Warn("could not wire DNS credentials", "err", err)
			}
		default:
			return nil, fmt.Errorf("unknown dns.cred %q (use reused, token, or file)", cred)
		}
	}

	recPath := filepath.Join(filepath.Dir(cfg.StatePath), "console-certificates.json")
	var list []map[string]any
	if b, err := os.ReadFile(recPath); err == nil {
		_ = json.Unmarshal(b, &list)
	}
	list = append(list, map[string]any{
		"name": name, "domains": domains, "profile": profile, "keyType": keyType, "uin": uin,
		"dns": dnsCfg,
	})
	b := marshalRegistry(list)
	if err := os.WriteFile(recPath, b, 0o600); err != nil {
		return nil, err
	}

	staged, err := stageCertificateInConfig(configPathForAdmin, name, domains, profile, keyType, uin, renewBefore, deploy)
	if err != nil {
		log.Warn("could not write the certificate into the config; console record only", "cert", name, "err", err)
		return map[string]any{"ok": true, "name": name, "status": "registered",
			"note": "saved to the console registry only: " + err.Error()}, nil
	}
	log.Info("certificate written to the config", "cert", name, "config", configPathForAdmin)
	if err := signalSelf(syscall.SIGHUP); err != nil {
		log.Warn("SIGHUP failed", "err", err)
	}
	return map[string]any{
		"ok": true, "name": name, "status": staged,
		"note": "added to " + configPathForAdmin + "; daemon reloading and reconciling now",
	}, nil
}

// renewBeforeToGoDuration maps the console's day-based choices onto the Go
// duration syntax the config parser accepts ("30d" is the classic typo and is
// rejected with "use hours"). Empty or unknown values fall back to the profile
// default by leaving the field unset.
func renewBeforeToGoDuration(s string) string {
	switch strings.TrimSpace(s) {
	case "7d", "7":
		return "168h"
	case "14d", "14":
		return "336h"
	case "30d", "30":
		return "720h"
	case "720h", "336h", "168h":
		return s
	case "", "<nil>":
		return ""
	default:
		// already a Go duration, or something the config parser will name
		if strings.HasSuffix(s, "h") || strings.HasSuffix(s, "m") {
			return s
		}
		return ""
	}
}

// stageCertificateInConfig appends one certificate to config.yaml's certificates list.
func stageCertificateInConfig(path, name string, domains []string, profile, keyType, uin, renewBefore, deploy string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("config path is unknown to this process")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := string(raw)
	if strings.Contains(text, "\n  - name: "+name+"\n") {
		return "already-present", nil
	}
	var sb strings.Builder
	sb.WriteString("\n  - name: ")
	sb.WriteString(name)
	sb.WriteString("\n    domains: [")
	for i, d := range domains {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(d)
	}
	sb.WriteString("]\n    profile: ")
	sb.WriteString(profile)
	sb.WriteString("\n    keyType: ")
	sb.WriteString(keyType)
	if renewBefore != "" {
		sb.WriteString("\n    renewBefore: ")
		sb.WriteString(renewBefore)
	}
	if uin != "" {
		sb.WriteString("\n    uin: ")
		sb.WriteString(uin)
	}
	// deploy=clb|nginx means "upload and let a human/agent bind"; deploy=none is
	// issue-only. The daemon's Deployer owns the Tencent SSL upload when enabled.
	sb.WriteString("\n    deploy:\n")
	switch deploy {
	case "clb", "nginx":
		sb.WriteString("      enabled: true\n")
		if deploy == "nginx" {
			sb.WriteString("      target: nginx\n")
		}
	default:
		sb.WriteString("      enabled: false\n")
	}
	block := sb.String()
	if strings.Contains(text, "certificates: []") {
		text = strings.Replace(text, "certificates: []", "certificates:\n"+block, 1)
	} else {
		text = text + block
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return "", err
	}
	return "added-to-config", nil
}

func deleteCertificateAdmin(cfg *config.Config, name string, log *slog.Logger) (any, error) {
	regPath := filepath.Join(filepath.Dir(cfg.StatePath), "console-certificates.json")
	var list []map[string]any
	if b, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(b, &list)
	}
	var kept []map[string]any
	for _, c := range list {
		if fmt.Sprint(c["name"]) == name {
			continue
		}
		kept = append(kept, c)
	}
	b := marshalRegistry(kept)
	_ = os.WriteFile(regPath, b, 0o600)
	if err := removeCertificateFromConfig(configPathForAdmin, name); err != nil {
		log.Warn("could not remove the certificate from the config", "cert", name, "err", err)
	} else {
		log.Info("certificate removed from the config", "cert", name)
		_ = signalSelf(syscall.SIGHUP)
	}
	// Drop the state row too. Leaving it makes every later pass log "no longer in
	// the desired state" and keeps the certificate in inventory after Delete.
	if openStateStore != nil {
		if err := openStateStore.DeleteCert(name); err != nil {
			log.Warn("could not remove the certificate from the state store", "cert", name, "err", err)
		} else {
			log.Info("certificate removed from the state store", "cert", name)
		}
	}
	return map[string]any{"ok": true, "name": name,
		"note": "removed from console registry, config.yaml and state store; daemon reloads"}, nil
}

func removeCertificateFromConfig(path, name string) error {
	if path == "" {
		return fmt.Errorf("config path is unknown to this process")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	skip := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if !skip && strings.HasPrefix(trimmed, "- name:") {
			got := strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:"))
			if got == name {
				skip = true
				continue
			}
		}
		if skip {
			if strings.HasPrefix(trimmed, "- name:") {
				skip = false
				out = append(out, line)
			}
			continue
		}
		out = append(out, line)
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o600)
}

func bindCertificateAdmin(cfg *config.Config, name string, body map[string]any, log *slog.Logger) (any, error) {
	lb, _ := body["loadBalancerId"].(string)
	lis, _ := body["listenerId"].(string)
	region, _ := body["region"].(string)
	sni, _ := body["sniDomain"].(string)
	if lb == "" || lis == "" {
		return nil, fmt.Errorf("loadBalancerId and listenerId are required")
	}
	if region == "" {
		region = "ap-guangzhou"
	}
	// Use the daemon's already-open store: opening a second handle would hit the
	// flock and fail with "already held by another wecert process".
	st := openStateStore
	if st == nil {
		return nil, fmt.Errorf("state store is not available to the admin surface yet")
	}
	rec, err := st.GetCert(name)
	if err != nil || rec == nil {
		return nil, fmt.Errorf("certificate %q is not in the state store; issue it first", name)
	}
	if len(rec.CertPEM) == 0 || len(rec.KeyPEM) == 0 {
		return nil, fmt.Errorf("certificate %q has no material in the state store yet — wait for issuance", name)
	}
	// A certificate that was issued with deploy disabled (or before deploy was
	// switched on) has no cloud id yet. Upload it here so the Bind button can
	// complete the documented first-issuance flow instead of bouncing the operator.
	if rec.DeployedCertID == "" {
		uploadedID, uerr := tencentUploadCertificate(name, rec.CertPEM, rec.KeyPEM)
		if uerr != nil {
			log.Error("CLB pre-bind upload failed", "cert", name, "err", uerr)
			return nil, fmt.Errorf("upload %q to Tencent Cloud SSL first: %w", name, uerr)
		}
		if err := st.UpdateCert(name, func(c *state.CertState) error {
			c.DeployedCertID = uploadedID
			return nil
		}); err != nil {
			log.Warn("uploaded but could not persist the cloud certificate id", "cert", name, "certId", uploadedID, "err", err)
		}
		rec.DeployedCertID = uploadedID
		log.Info("uploaded certificate for console bind", "cert", name, "certId", uploadedID)
	}
	if err := tencentBindListener(region, lb, lis, rec.DeployedCertID, sni); err != nil {
		log.Error("CLB bind failed", "cert", name, "lb", lb, "listener", lis, "err", err)
		return nil, err
	}
	log.Info("CLB bind succeeded", "cert", name, "certId", rec.DeployedCertID, "lb", lb, "listener", lis)
	return map[string]any{
		"ok": true, "name": name, "loadBalancerId": lb, "listenerId": lis,
		"deployedCertId": rec.DeployedCertID, "sniDomain": sni,
		"note": "certificate attached to the CLB listener via the cloud API",
	}, nil
}

func unbindCertificateAdmin(cfg *config.Config, name string, log *slog.Logger) (any, error) {
	log.Info("console unbind request", "name", name)
	return map[string]any{"ok": true, "name": name,
		"note": "certificate stays in inventory; detach it from the listener in the cloud if required"}, nil
}

// tencentUploadCertificate pushes the local full chain + key into Tencent Cloud
// SSL and returns the new CertificateId. Used by the console Bind path when a
// certificate was issued but never uploaded (deploy was off at issue time).
func tencentUploadCertificate(name string, certPEM, keyPEM []byte) (string, error) {
	cred, err := adminCred()
	if err != nil {
		return "", err
	}
	client, err := ssl.NewClient(cred, "", profile.NewClientProfile())
	if err != nil {
		return "", err
	}
	req := ssl.NewUploadCertificateRequest()
	req.CertificatePublicKey = common.StringPtr(string(certPEM))
	req.CertificatePrivateKey = common.StringPtr(string(keyPEM))
	req.Alias = common.StringPtr(name)
	resp, err := client.UploadCertificate(req)
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Response == nil {
		return "", fmt.Errorf("UploadCertificate returned an empty response")
	}
	if resp.Response.CertificateId != nil && *resp.Response.CertificateId != "" {
		return *resp.Response.CertificateId, nil
	}
	if resp.Response.RepeatCertId != nil && *resp.Response.RepeatCertId != "" {
		return *resp.Response.RepeatCertId, nil
	}
	return "", fmt.Errorf("UploadCertificate returned neither a CertificateId nor a RepeatCertId")
}

func tencentBindListener(region, lb, listener, certID, sni string) error {
	cred, err := adminCred()
	if err != nil {
		return err
	}
	client, err := clb.NewClient(cred, region, profile.NewClientProfile())
	if err != nil {
		return err
	}
	// SNI listeners carry per-domain certificates. Prefer attaching to the named
	// domain; create the rule when the console offered a name the listener does
	// not have yet (the first Bind for a newly issued certificate).
	// CertificateInput.SSLMode is required on CreateRule even for a plain
	// server-cert bind — omitting it fails with "Lack of parameter Certificate.SSLMode".
	if sni != "" {
		certIn := &clb.CertificateInput{CertId: &certID, SSLMode: common.StringPtr("UNIDIRECTIONAL")}
		dreq := clb.NewModifyDomainAttributesRequest()
		dreq.LoadBalancerId = &lb
		dreq.ListenerId = &listener
		dreq.Domain = &sni
		dreq.Certificate = certIn
		if _, err := client.ModifyDomainAttributes(dreq); err == nil {
			return nil
		}
		// Domain missing — create the forwarding rule with the certificate already set.
		creq := clb.NewCreateRuleRequest()
		creq.LoadBalancerId = &lb
		creq.ListenerId = &listener
		creq.Rules = []*clb.RuleInput{{
			Domain:      &sni,
			Url:         common.StringPtr("/"),
			Certificate: certIn,
		}}
		if _, err := client.CreateRule(creq); err != nil {
			return fmt.Errorf("create SNI rule for %s: %w", sni, err)
		}
		// CreateRule already carries the certificate. Re-asserting it immediately
		// races the async AddQLBLocation task ("ResourceInOperating") and would
		// turn a successful create into a failed bind. The daemon's binding
		// patrol confirms the mount independently.
		return nil
	}
	req := clb.NewModifyListenerRequest()
	req.LoadBalancerId = &lb
	req.ListenerId = &listener
	req.Certificate = &clb.CertificateInput{CertId: &certID, SSLMode: common.StringPtr("UNIDIRECTIONAL")}
	_, err = client.ModifyListener(req)
	return err
}

func adminCred() (common.CredentialIface, error) {
	id := os.Getenv("TENCENTCLOUD_SECRET_ID")
	key := os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if id == "" || key == "" {
		return nil, fmt.Errorf("no Tencent Cloud credentials in the daemon environment")
	}
	return common.NewCredential(id, key), nil
}

// wireDNSCredentials points the matching credential-file key at tokenFile and
// sets dns.provider when one is named. Only the key that belongs to the selected
// provider is touched — the other providers' credential blocks stay as they are.
func wireDNSCredentials(path, provider, tokenFile string) error {
	if path == "" {
		return fmt.Errorf("config path is unknown")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(raw)

	var key string
	switch provider {
	case "cloudflare", "":
		key = "apiTokenFile"
	case "dnspod":
		key = "loginTokenFile"
	case "tencentcloud":
		// tencentcloud DNS uses the account SecretKey, not a dedicated token file;
		// fall through to secretAccessKeyFile only when the operator named it.
		key = "secretAccessKeyFile"
	case "route53":
		key = "secretAccessKeyFile"
	default:
		key = "apiTokenFile"
	}

	lines := strings.Split(text, "\n")
	found := false
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
		lines[i] = indent + key + ": " + tokenFile
		found = true
		break
	}
	if found {
		text = strings.Join(lines, "\n")
	}
	if provider != "" {
		text = setYAMLScalar(text, "provider", provider)
	}
	return os.WriteFile(path, []byte(text), 0o600)
}

// setYAMLScalar replaces a top-level-looking `key: value` line (first match at
// any indent under the dns block is not needed here: `provider` is unique enough
// in wecert's config). Used only for dns.provider.
func setYAMLScalar(text, key, value string) string {
	lines := strings.Split(text, "\n")
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, key+":") {
			indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " \t"))]
			lines[i] = indent + key + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	return text
}

func signalSelf(sig os.Signal) error {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return proc.Signal(sig)
}
