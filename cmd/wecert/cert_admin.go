package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/susunola/wecert/internal/atomicfile"
	"gopkg.in/yaml.v3"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
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

// safePathComponent rejects names that would escape a directory when joined
// into a file path. A console-supplied name is not a trusted path element.
func safePathComponent(what, s string) error {
	if s == "" {
		return webhook.InvalidRequestf("%s is required", what)
	}
	if strings.ContainsAny(s, "/\\\x00\n\r") {
		return webhook.InvalidRequestf("%s must not contain path separators or control characters", what)
	}
	if s == "." || s == ".." {
		return webhook.InvalidRequestf("%s is reserved", what)
	}
	if filepath.Base(s) != s {
		return webhook.InvalidRequestf("%s must be a single path element", what)
	}
	return nil
}

// accountKeyPath derives where an account's AK/SK file lives. The request may
// name a path, but it is confined to the accounts directory: a caller that
// could pick any absolute path would have arbitrary file write as root.
func accountKeyPath(statePath, name, requested string) (string, error) {
	if err := safePathComponent("name", name); err != nil {
		return "", err
	}
	root := filepath.Join(filepath.Dir(statePath), "accounts")
	derived := filepath.Join(root, name+".key")
	if requested == "" {
		return derived, nil
	}
	clean := filepath.Clean(requested)
	if !filepath.IsAbs(clean) {
		return "", webhook.InvalidRequestf("keyPath must be an absolute path")
	}
	if clean != derived && !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return "", webhook.InvalidRequestf("keyPath must live under the accounts directory")
	}
	// The lexical prefix check is not enough by itself: a symlinked directory
	// under accounts/ still passes it while redirecting the AK/SK write outside
	// the root. Resolve the ancestor chain that already exists; a directory that
	// does not exist yet is created by MkdirAll and has no symlink to smuggle
	// the write through.
	if resolvedRoot, err := filepath.EvalSymlinks(root); err == nil {
		if resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
			if resolvedParent != resolvedRoot &&
				!strings.HasPrefix(resolvedParent, resolvedRoot+string(filepath.Separator)) {
				return "", webhook.InvalidRequestf("keyPath must resolve inside the accounts directory")
			}
		}
	}
	return clean, nil
}

// certificateEntry is the YAML shape written into config.yaml. Marshalling it
// with gopkg.in/yaml.v3 (rather than string concatenation) is what stops a
// name or domain carrying a newline from injecting new config keys.
type certificateEntry struct {
	Name        string   `yaml:"name"`
	Domains     []string `yaml:"domains"`
	Profile     string   `yaml:"profile"`
	KeyType     string   `yaml:"keyType"`
	RenewBefore string   `yaml:"renewBefore,omitempty"`
	UIN         string   `yaml:"uin,omitempty"`
	Deploy      struct {
		Enabled bool   `yaml:"enabled"`
		Target  string `yaml:"target,omitempty"`
	} `yaml:"deploy"`
}

// certificateNode renders one certificate entry as a YAML mapping node. Building
// the node from a typed struct (rather than splicing a string) is what stops a
// name or domain carrying a newline from injecting new config keys, and what lets
// the entry sit in the certificates sequence as a real node for the tree edit.
func certificateNode(name string, domains []string, profile, keyType, renewBefore, uin, deploy string) (*yaml.Node, error) {
	if err := safePathComponent("name", name); err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, webhook.InvalidRequestf("at least one domain is required")
	}
	for _, d := range domains {
		if d == "" {
			return nil, webhook.InvalidRequestf("domains must not contain empty entries")
		}
		if err := config.ValidateDomain(d); err != nil {
			return nil, webhook.InvalidRequestf("invalid domain %q: %v", d, err)
		}
	}
	var e certificateEntry
	e.Name = name
	e.Domains = domains
	e.Profile = profile
	e.KeyType = keyType
	e.RenewBefore = renewBefore
	e.UIN = uin
	e.Deploy.Enabled, e.Deploy.Target = webhook.ResolveDeploy(deploy)
	raw, err := yaml.Marshal(e)
	if err != nil {
		return nil, err
	}
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, err
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("certificate entry did not encode to a single mapping")
	}
	return node.Content[0], nil
}

// registerCertAdminOps fills the certificate/account management seams the web
// console calls. Called from adminOps so the wiring lives in one place.
func registerCertAdminOps(ops *webhook.AdminOps, cfg *config.Config, log *slog.Logger) {
	ops.Notifications = notificationSettings
	ops.ListAccounts = func(ctx context.Context) (any, error) {
		return listCloudAccounts(cfg)
	}
	ops.AddAccount = func(ctx context.Context, body webhook.AddAccountRequest) (any, error) {
		return addCloudAccount(cfg, body, log)
	}
	ops.RemoveAccount = func(ctx context.Context, uin string) (any, error) {
		return removeCloudAccount(cfg, uin, log)
	}
	ops.ListBindings = func(ctx context.Context) (any, error) {
		return listCloudBindings(cfg)
	}
	ops.CreateCertificate = func(ctx context.Context, body webhook.CreateCertificateRequest) (any, error) {
		return createCertificateAdmin(cfg, body, log)
	}
	ops.DeleteCertificate = func(ctx context.Context, name string) (any, error) {
		return deleteCertificateAdmin(cfg, name, log)
	}
	ops.BindCertificate = func(ctx context.Context, name string, body webhook.BindCertificateRequest) (any, error) {
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

func addCloudAccount(cfg *config.Config, body webhook.AddAccountRequest, log *slog.Logger) (any, error) {
	configMu.Lock()
	defer configMu.Unlock()
	name, uin, cred := body.Name, body.UIN, body.Cred
	cloud, secretID, secretKey := body.Cloud, body.SecretID, body.SecretKey
	site := strings.ToLower(strings.TrimSpace(body.Site))
	requestedKey := body.KeyPath
	// UIN is optional for static AK/SK: it is a display/grouping label here, and
	// forcing it made operators invent a number the API would have filled in.
	if uin == "" && cred != "static" {
		return nil, webhook.InvalidRequestf("uin is required for credential method %q", cred)
	}
	if name == "" {
		if uin != "" {
			name = "account-" + uin
		} else {
			name = "account"
		}
	}
	keyPath, err := accountKeyPath(cfg.StatePath, name, requestedKey)
	if err != nil {
		return nil, err
	}
	if cred == "static" && secretID != "" {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return nil, err
		}
		payload := "TENCENTCLOUD_SECRET_ID=" + secretID + "\nTENCENTCLOUD_SECRET_KEY=" + secretKey + "\n"
		if err := atomicfile.Write(keyPath, []byte(payload), 0o600); err != nil {
			return nil, err
		}
		log.Info("wrote cloud account credentials", "path", keyPath, "uin", uin, "cloud", cloud)
	}
	if uin == "" {
		uin = "auto:" + name
	}
	list, err := webhook.ReadCloudAccounts(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	list = append(list, webhook.CloudAccount{
		Name: name, UIN: uin, Cred: cred, Cloud: cloud, Site: site, KeyPath: keyPath,
	})
	if err := webhook.WriteCloudAccounts(cfg.StatePath, list); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "name": name, "uin": uin, "cloud": cloud, "keyPath": keyPath,
		"note": "AK/SK stored as 0600 on the daemon host; never echoed back"}, nil
}

func removeCloudAccount(cfg *config.Config, uin string, log *slog.Logger) (any, error) {
	configMu.Lock()
	defer configMu.Unlock()
	list, err := webhook.ReadCloudAccounts(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	kept := make([]webhook.CloudAccount, 0, len(list))
	removed := 0
	for _, a := range list {
		if a.UIN == uin {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	if err := webhook.WriteCloudAccounts(cfg.StatePath, kept); err != nil {
		return nil, err
	}
	log.Info("removed cloud account", "uin", uin, "removed", removed)
	return map[string]any{"ok": true, "removed": removed}, nil
}

// listCloudBindings reports CLB bindings. The inventory already derives them
// from the state store and the live bind-resource enumeration, so this stays an
// empty placeholder for the console's bindings panel rather than a second
// enumeration path.
// listCloudBindings enumerates the account's load balancers and their listeners
// so the console's Bind dialog can offer a real choice instead of asking the
// operator to paste an id.
func listCloudBindings(cfg *config.Config) (any, error) {
	cred, err := adminCred()
	if err != nil {
		return nil, err
	}
	regions := cfg.Tencent.Regions
	if len(regions) == 0 {
		regions = []string{"ap-guangzhou"}
	}
	type listener struct {
		ID    string `json:"id"`
		Proto string `json:"proto"`
		Port  int    `json:"port"`
		SNI   bool   `json:"sni"`
	}
	type lb struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		Region    string     `json:"region"`
		Listeners []listener `json:"listeners"`
	}
	site := resolveTencentSite(cred, regions[0], "")
	out := make([]lb, 0, 8)
	for _, region := range regions {
		client, err := clb.NewClient(cred, region, tencentProfile(site))
		if err != nil {
			return nil, fmt.Errorf("clb client for %s: %w", region, err)
		}
		var offset int64
		for {
			req := clb.NewDescribeLoadBalancersRequest()
			req.Offset = common.Int64Ptr(offset)
			req.Limit = common.Int64Ptr(20)
			resp, err := client.DescribeLoadBalancers(req)
			if err != nil {
				return nil, fmt.Errorf("describe load balancers in %s: %w", region, err)
			}
			if resp == nil || resp.Response == nil {
				break
			}
			set := resp.Response.LoadBalancerSet
			for _, b := range set {
				if b == nil || b.LoadBalancerId == nil {
					continue
				}
				entry := lb{ID: *b.LoadBalancerId, Region: region}
				if b.LoadBalancerName != nil {
					entry.Name = *b.LoadBalancerName
				}
				lreq := clb.NewDescribeListenersRequest()
				lreq.LoadBalancerId = b.LoadBalancerId
				lresp, err := client.DescribeListeners(lreq)
				if err == nil && lresp != nil && lresp.Response != nil {
					for _, l := range lresp.Response.Listeners {
						if l == nil || l.ListenerId == nil {
							continue
						}
						item := listener{ID: *l.ListenerId}
						if l.Protocol != nil {
							item.Proto = *l.Protocol
						}
						if l.Port != nil {
							item.Port = int(*l.Port)
						}
						if l.SniSwitch != nil && *l.SniSwitch == 1 {
							item.SNI = true
						}
						entry.Listeners = append(entry.Listeners, item)
					}
				}
				out = append(out, entry)
			}
			if len(set) < 20 {
				break
			}
			offset += int64(len(set))
		}
	}
	return map[string]any{"bindings": out, "site": site}, nil
}

func createCertificateAdmin(cfg *config.Config, body webhook.CreateCertificateRequest, log *slog.Logger) (any, error) {
	configMu.Lock()
	defer configMu.Unlock()
	name := body.Name
	// Validate before the name reaches a file path or a YAML block.
	if err := safePathComponent("name", name); err != nil {
		return nil, err
	}
	domains := body.Domains
	if len(domains) == 0 {
		return nil, webhook.InvalidRequestf("at least one domain is required")
	}
	for _, d := range domains {
		if err := config.ValidateDomain(d); err != nil {
			return nil, webhook.InvalidRequestf("invalid domain %q: %v", d, err)
		}
	}
	profile := body.Profile
	if profile == "" {
		profile = "classic"
	}
	keyType := body.KeyType
	if keyType == "" {
		keyType = "ecdsa-p256"
	}
	uin := body.UIN
	renewBefore := renewBeforeToGoDuration(body.RenewBefore)
	deploy := body.Deploy
	dnsCfg := body.DNS

	// DNS token / file → 0600 file + config wiring so DNS-01 can run.
	// cred=reused leaves the daemon's existing dns block untouched.
	if dnsCfg != nil {
		switch dnsCfg.Cred {
		case "reused", "":
			// keep whatever dns.* the daemon already has
		case "token":
			if dnsCfg.Token == "" {
				return nil, webhook.InvalidRequestf("dns.cred=token requires dns.token")
			}
			tokPath := filepath.Join(filepath.Dir(cfg.StatePath), "dns", name+".token")
			if err := os.MkdirAll(filepath.Dir(tokPath), 0o700); err != nil {
				return nil, fmt.Errorf("create dns credential dir: %w", err)
			}
			if err := atomicfile.Write(tokPath, []byte(dnsCfg.Token), 0o600); err != nil {
				return nil, fmt.Errorf("store DNS token: %w", err)
			}
			log.Info("stored DNS token", "cert", name, "path", tokPath)
			if err := wireDNSCredentials(configPathForAdmin, dnsCfg.Provider, tokPath); err != nil {
				log.Warn("could not wire DNS credentials", "err", err)
			}
		case "file":
			if dnsCfg.File == "" {
				return nil, webhook.InvalidRequestf("dns.cred=file requires dns.file")
			}
			if err := wireDNSCredentials(configPathForAdmin, dnsCfg.Provider, dnsCfg.File); err != nil {
				log.Warn("could not wire DNS credentials", "err", err)
			}
		default:
			return nil, webhook.InvalidRequestf("unknown dns.cred %q (use reused, token, or file)", dnsCfg.Cred)
		}
	}

	list, err := webhook.ReadConsoleCertificates(cfg.StatePath)
	if err != nil {
		// A corrupt registry must not be rewritten as a shorter list: that is how
		// every previously recorded certificate disappears.
		return nil, err
	}
	// Persist the credential kind, never the secret: the token is already in a
	// 0600 file under dns/.
	rec := webhook.ConsoleCertificate{
		Name: name, Domains: domains, Profile: profile, KeyType: keyType, UIN: uin,
		Deploy: strings.TrimSpace(deploy),
	}
	if dnsCfg != nil {
		san := dnsCfg.Sanitized()
		rec.DNS = &san
	}
	list = append(list, rec)
	if err := webhook.WriteConsoleCertificates(cfg.StatePath, list); err != nil {
		return nil, err
	}

	staged, err := stageCertificateInConfig(configPathForAdmin, name, domains, profile, keyType, uin, renewBefore, deploy)
	if err != nil {
		// The registry row is already written, but the daemon config is not: the
		// certificate will not be issued, so reporting ok:true would lie to the
		// operator. Fail loudly instead.
		log.Error("could not write the certificate into the config", "cert", name, "err", err)
		return nil, fmt.Errorf("certificate recorded in the console registry, but writing the daemon config failed; fix the configuration and retry: %w", err)
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
	case "":
		return ""
	default:
		// already a Go duration, or something the config parser will name
		if strings.HasSuffix(s, "h") || strings.HasSuffix(s, "m") {
			return s
		}
		return ""
	}
}

// isEmptySequence reports whether a certificates: node holds no entries: either
// the key was written with nothing under it (which parses as null) or it is an
// explicitly empty list. Both mean "no certificates yet", never "malformed".
func isEmptySequence(node *yaml.Node) bool {
	if node == nil {
		return true
	}
	if node.Kind == yaml.SequenceNode {
		return len(node.Content) == 0
	}
	return node.Kind == yaml.ScalarNode && (node.Tag == "!!null" || strings.TrimSpace(node.Value) == "")
}

// stageCertificateInConfig appends one certificate to config.yaml's certificates
// list by editing the YAML tree, exactly as removal does. Editing the tree
// (rather than splicing text) keeps the document valid whether the list is
// written inline (certificates: [{...}]) or with any indentation, and makes
// "already present" compare parsed names instead of bytes -- so `name: "x"` and
// `name: x` are the same certificate, not two.
func stageCertificateInConfig(path, name string, domains []string, profile, keyType, uin, renewBefore, deploy string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("config path is unknown to this process")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("invalid configuration")
	}
	root := doc.Content[0]
	certs := yamlFind(root, "certificates")
	if certs == nil {
		certs = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "certificates"},
			certs)
	} else if certs.Kind != yaml.SequenceNode {
		// "certificates:" with nothing under it parses as null, and that is how
		// a hand-written or freshly installed config says "no certificates yet".
		// Refusing it would strand the console's create form on a daemon that is
		// otherwise running fine (a null list is not an empty one).
		if !isEmptySequence(certs) {
			return "", fmt.Errorf("configuration certificates must be a list")
		}
		certs.Kind = yaml.SequenceNode
		certs.Tag = "!!seq"
		certs.Value = ""
		certs.Content = nil
	}
	// Force block style so an inline certificates: [{...}] is rewritten as a
	// block list before a new entry is appended -- splicing a block item into a
	// flow sequence is what produced a document the parser rejected.
	certs.Style = 0
	for _, item := range certs.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if got := yamlFind(item, "name"); got != nil && got.Value == name {
			return "already-present", nil
		}
	}
	entry, err := certificateNode(name, domains, profile, keyType, renewBefore, uin, deploy)
	if err != nil {
		return "", err
	}
	certs.Content = append(certs.Content, entry)
	updated, err := encodeYAML(&doc)
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(path, updated, 0o600); err != nil {
		return "", err
	}
	return "added-to-config", nil
}

func deleteCertificateAdmin(cfg *config.Config, name string, log *slog.Logger) (any, error) {
	configMu.Lock()
	defer configMu.Unlock()
	// Observe diffs reality against the configured list, so an empty one is
	// meaningless there and the reload admission gate would reject it after
	// this function had already written config.yaml -- leaving the file and the
	// running state diverged. Static may end empty (console-first cold start:
	// the first certificate is created from the browser afterwards), so only
	// observe is refused here, before the write. cfg is the snapshot the
	// process started with, so re-read the file: earlier management writes may
	// have changed the list since.
	current, err := config.Load(configPathForAdmin)
	if err != nil {
		return nil, fmt.Errorf("cannot re-read the current configuration: %w", err)
	}
	if current.DesiredState.Mode == config.ModeObserve && len(current.Certificates) <= 1 {
		return nil, webhook.InvalidRequestf(
			"refusing to delete %s: desiredState.mode=%q diffs reality against the configured list and needs at least one certificate",
			name, current.DesiredState.Mode)
	}
	list, err := webhook.ReadConsoleCertificates(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate registry: %w", err)
	}
	kept := make([]webhook.ConsoleCertificate, 0, len(list))
	for _, c := range list {
		if c.Name == name {
			continue
		}
		kept = append(kept, c)
	}
	if err := removeCertificateFromConfig(configPathForAdmin, name); err != nil {
		return nil, err
	}
	if err := webhook.WriteConsoleCertificates(cfg.StatePath, kept); err != nil {
		return nil, fmt.Errorf("removed from config, but registry cleanup failed: %w", err)
	}
	// Drop the state row too. Leaving it makes every later pass log "no longer in
	// the desired state" and keeps the certificate in inventory after Delete.
	if openStateStore != nil {
		if err := openStateStore.DeleteCert(name); err != nil {
			return nil, fmt.Errorf("removed from config, but state cleanup failed: %w", err)
		} else {
			log.Info("certificate removed from the state store", "cert", name)
		}
	}
	if err := signalSelf(syscall.SIGHUP); err != nil {
		return nil, fmt.Errorf("removed, but daemon reload failed: %w", err)
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
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("invalid configuration")
	}
	certs := yamlFind(doc.Content[0], "certificates")
	// A certificate that exists only in the console registry -- because the
	// create that recorded it never reached the config, or because the list is
	// empty -- must still be removable from the registry and the state store.
	// Reporting an error here leaves a row the operator can see and not delete.
	if certs == nil || isEmptySequence(certs) {
		return nil
	}
	if certs.Kind != yaml.SequenceNode {
		return fmt.Errorf("configuration has no certificate list")
	}
	kept := make([]*yaml.Node, 0, len(certs.Content))
	for _, item := range certs.Content {
		if item.Kind != yaml.MappingNode {
			return fmt.Errorf("invalid certificate entry")
		}
		if got := yamlFind(item, "name"); got == nil || got.Value != name {
			kept = append(kept, item)
		}
	}
	certs.Content = kept
	updated, err := encodeYAML(&doc)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, updated, 0600)
}

func bindCertificateAdmin(cfg *config.Config, name string, body webhook.BindCertificateRequest, log *slog.Logger) (any, error) {
	lb := body.LoadBalancerID
	lis := body.ListenerID
	region := body.Region
	sni := body.SNIDomain
	createRaw := body.CreateListener
	if lis == "" && createRaw == nil {
		return nil, webhook.InvalidRequestf("listenerId is required")
	}
	if lb == "" {
		return nil, webhook.InvalidRequestf("loadBalancerId is required")
	}
	if region == "" {
		return nil, webhook.InvalidRequestf("region is required")
	}
	current, err := config.Load(configPathForAdmin)
	if err != nil {
		return nil, fmt.Errorf("cannot verify certificate account from configuration")
	}
	expected := ""
	for _, cert := range current.Certificates {
		if cert.Name == name {
			expected = cert.UIN
			if expected == "" {
				expected = current.Tencent.UIN
			}
			break
		}
	}
	if err := verifyBindingAccount(expected, region); err != nil {
		return nil, err
	}
	site := siteForAccount(cfg, expected)
	// Use the daemon's already-open store: opening a second handle would hit the
	// flock and fail with "already held by another wecert process".
	st := openStateStore
	if st == nil {
		return nil, fmt.Errorf("state store is not available to the admin surface yet")
	}
	rec, err := st.GetCert(name)
	if err != nil || rec == nil {
		return nil, webhook.InvalidRequestf("certificate %q is not in the state store; issue it first", name)
	}
	if len(rec.CertPEM) == 0 || len(rec.KeyPEM) == 0 {
		return nil, webhook.InvalidRequestf("certificate %q has no material in the state store yet — wait for issuance", name)
	}
	// A certificate that was issued with deploy disabled (or before deploy was
	// switched on) has no cloud id yet. Upload it here so the Bind button can
	// complete the documented first-issuance flow instead of bouncing the operator.
	if rec.DeployedCertID == "" {
		uploadedID, uerr := tencentUploadCertificate(name, rec.CertPEM, rec.KeyPEM, site)
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
	// Optional: create a brand-new HTTPS listener before attaching. The console
	// offers this when the CLB has no suitable listener yet.
	createdListener := ""
	if lis == "" {
		if createRaw == nil {
			return nil, webhook.InvalidRequestf("listenerId is required unless createListener is set")
		}
		port := int64(createRaw.Port)
		if port == 0 {
			port = 443
		}
		if port < 1 || port > 65535 {
			return nil, webhook.InvalidRequestf("createListener.port must be 1-65535, got %d", port)
		}
		lname := createRaw.Name
		// SNI is the default for a multi-name console flow; sni=false makes the
		// certificate the listener's default (Certificate only applies then).
		sniOn := createRaw.SNIMode()
		newID, cerr := tencentCreateHTTPSListener(region, lb, port, lname, sniOn, rec.DeployedCertID, site)
		if cerr != nil {
			log.Error("CLB create listener failed", "cert", name, "lb", lb, "port", port, "err", cerr)
			return nil, fmt.Errorf("create HTTPS listener on %s: %w", lb, cerr)
		}
		lis = newID
		createdListener = newID
		log.Info("CLB listener created", "cert", name, "lb", lb, "listener", lis, "port", port, "sni", sniOn)
	}
	if lis == "" {
		return nil, fmt.Errorf("listenerId is required")
	}
	if err := tencentBindListener(region, lb, lis, rec.DeployedCertID, sni, site); err != nil {
		log.Error("CLB bind failed", "cert", name, "lb", lb, "listener", lis, "err", err)
		return nil, err
	}
	log.Info("CLB bind succeeded", "cert", name, "certId", rec.DeployedCertID, "lb", lb, "listener", lis)
	return map[string]any{
		"ok": true, "name": name, "loadBalancerId": lb, "listenerId": lis,
		"createdListener": createdListener,
		"deployedCertId":  rec.DeployedCertID, "sniDomain": sni,
		"note": "certificate attached to the CLB listener via the cloud API",
	}, nil
}

func verifyBindingAccount(expected, region string) error {
	if expected == "" {
		return fmt.Errorf("certificate UIN is unknown; binding refused")
	}
	cred, err := adminCred()
	if err != nil {
		return err
	}
	p := profile.NewClientProfile()
	p.HttpProfile.Endpoint = "sts.tencentcloudapi.com"
	p.HttpProfile.ReqTimeout = 10
	client := new(common.Client).Init(region).WithCredential(cred).WithProfile(p)
	response := tchttp.NewCommonResponse()
	if err = client.Send(tchttp.NewCommonRequest("sts", "2018-08-13", "GetCallerIdentity"), response); err != nil {
		return fmt.Errorf("cannot verify cloud credential ownership; binding refused")
	}
	var identity struct {
		Response struct {
			AccountID string `json:"AccountId"`
		} `json:"Response"`
	}
	if json.Unmarshal(response.GetBody(), &identity) != nil || identity.Response.AccountID != expected {
		return fmt.Errorf("daemon credentials do not belong to certificate UIN %s; binding refused", expected)
	}
	return nil
}

// tencentCreateHTTPSListener opens a new HTTPS listener. With sniOn the
// certificate is attached per-domain (CreateRule later); without SNI it becomes
// the listener default, which is the only place Certificate is accepted.
func tencentCreateHTTPSListener(region, lb string, port int64, name string, sniOn bool, certID, site string) (string, error) {
	cred, err := adminCred()
	if err != nil {
		return "", err
	}
	client, err := clb.NewClient(cred, region, tencentProfile(site))
	if err != nil {
		return "", err
	}
	req := clb.NewCreateListenerRequest()
	req.LoadBalancerId = &lb
	req.Protocol = common.StringPtr("HTTPS")
	req.Ports = []*int64{common.Int64Ptr(port)}
	if name != "" {
		req.ListenerNames = []*string{common.StringPtr(name)}
	}
	if sniOn {
		req.SniSwitch = common.Int64Ptr(1)
	} else {
		req.SniSwitch = common.Int64Ptr(0)
		req.Certificate = &clb.CertificateInput{
			CertId:  &certID,
			SSLMode: common.StringPtr("UNIDIRECTIONAL"),
		}
	}
	resp, err := client.CreateListener(req)
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Response == nil || len(resp.Response.ListenerIds) == 0 {
		return "", fmt.Errorf("CreateListener returned no listener id")
	}
	for _, id := range resp.Response.ListenerIds {
		if id != nil && *id != "" {
			return *id, nil
		}
	}
	return "", fmt.Errorf("CreateListener returned empty listener ids")
}

func unbindCertificateAdmin(cfg *config.Config, name string, log *slog.Logger) (any, error) {
	log.Info("console unbind request", "name", name)
	return map[string]any{"ok": true, "name": name,
		"note": "certificate stays in inventory; detach it from the listener in the cloud if required"}, nil
}

// tencentUploadCertificate pushes the local full chain + key into Tencent Cloud
// SSL and returns the new CertificateId. Used by the console Bind path when a
// certificate was issued but never uploaded (deploy was off at issue time).
func tencentUploadCertificate(name string, certPEM, keyPEM []byte, site string) (string, error) {
	cred, err := adminCred()
	if err != nil {
		return "", err
	}
	client, err := ssl.NewClient(cred, "", tencentProfile(site))
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

func tencentBindListener(region, lb, listener, certID, sni, site string) error {
	cred, err := adminCred()
	if err != nil {
		return err
	}
	client, err := clb.NewClient(cred, region, tencentProfile(site))
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

// tencentRootDomain maps the account's site onto the API root domain. Tencent
// Cloud runs two separate account systems: the domestic one answers on
// tencentcloudapi.com, the international one on intl.tencentcloudapi.com. A
// wrong site looks exactly like bad credentials.
func tencentRootDomain(site string) string {
	switch strings.ToLower(strings.TrimSpace(site)) {
	case "international", "intl":
		return "intl.tencentcloudapi.com"
	default:
		// "" (auto) and "china" both use the domestic root domain.
		return "tencentcloudapi.com"
	}
}

// siteForAccount returns the site recorded with a stored account, or "".
func siteForAccount(cfg *config.Config, uin string) string {
	if uin == "" {
		return ""
	}
	accounts, err := webhook.ReadCloudAccounts(cfg.StatePath)
	if err != nil {
		return ""
	}
	for _, a := range accounts {
		if a.UIN == uin {
			return a.Site
		}
	}
	return ""
}

// tencentProfile builds the client profile for one site. The root domain is the
// whole difference between the two Tencent Cloud account systems.
func tencentProfile(site string) *profile.ClientProfile {
	p := profile.NewClientProfile()
	p.HttpProfile.RootDomain = tencentRootDomain(site)
	return p
}

// resolveTencentSite answers which of the two Tencent Cloud sites these
// credentials belong to. "" means auto: try the domestic root domain first and
// fall back to the international one. A wrong site surfaces as an auth error,
// which is indistinguishable from bad keys without this probe.
func resolveTencentSite(cred common.CredentialIface, region, site string) string {
	if site != "" {
		return site
	}
	probe := func(root string) bool {
		p := profile.NewClientProfile()
		p.HttpProfile.RootDomain = root
		client, err := clb.NewClient(cred, region, p)
		if err != nil {
			return false
		}
		req := clb.NewDescribeLoadBalancersRequest()
		req.Limit = common.Int64Ptr(1)
		_, err = client.DescribeLoadBalancers(req)
		return err == nil
	}
	if probe("tencentcloudapi.com") {
		return "china"
	}
	if probe("intl.tencentcloudapi.com") {
		return "international"
	}
	return "china"
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
	return atomicfile.Write(path, []byte(text), 0o600)
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

// signalSelf is a variable so tests can stub the reload signal: the real one
// sends SIGHUP to this process, which under `go test` is the test binary.
var signalSelf = func(sig os.Signal) error {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return proc.Signal(sig)
}
