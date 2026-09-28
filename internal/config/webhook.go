package config

import ()

// Metrics is the Prometheus exposition configuration.
type Metrics struct {
	Listen string `yaml:"listen"`
}

// Webhook lets wecert be triggered by external events, not only by polling.
//
// Typical use: call it once from CI or an event bus after a domain is added,
// rather than waiting for the next top of the hour.
type Webhook struct {
	// Listen is the listen address of the trigger endpoint. Empty disables the
	// webhook.
	Listen string `yaml:"listen"`

	// Token is the shared secret and is required.
	//
	// This endpoint triggers real issuance and consumes Let's Encrypt rate-limit
	// quota, so it must never be left unauthenticated. Two forms are accepted:
	//   Authorization: Bearer <token>
	//   X-Wecert-Token: <token>
	Token string `yaml:"token"`

	// TokenFile reads the token from a file instead, for the same reason as
	// dns.loginTokenFile: a 0600 file or a systemd credential keeps the secret out of
	// config.yaml and its backups. Environment-expanded; mutually exclusive with token.
	TokenFile string `yaml:"tokenFile,omitempty"`

	// NotifyURL is optional. When set, every finished renewal attempt POSTs a JSON
	// event to it, to wire "certificate renewed" into downstream flows (triggering
	// a config reload, for example).
	NotifyURL string `yaml:"notifyURL"`

	// NotifySecret is optional and only meaningful with NotifyURL. When set, each
	// notification carries X-Wecert-Signature: sha256=<hex HMAC-SHA256 of the raw
	// body>, which lets the receiver distinguish a genuine event from anything else
	// that can reach its URL.
	NotifySecret string `yaml:"notifySecret"`

	// AdminToken is a SECOND shared secret for the guarded write/diagnostic surface
	// (/admin/...). Optional: without it the admin routes are not mounted, and the
	// process stays read-only over the network.
	//
	// Deliberately separate from Token: the read-only token is what a CI job holds to
	// poll status; the admin token is what can restore a snapshot. Sharing one would
	// give every status poller the ability to overwrite state.db.
	AdminToken string `yaml:"adminToken,omitempty"`

	// NotifyFormat selects the POST body shape. "" or "generic" is the documented
	// JSON event (and the only format that carries X-Wecert-Signature over the raw
	// body the receiver is expected to verify). The others are the wire formats
	// those products actually accept, so an operator does not have to run a
	// translator in front of a chat webhook:
	//   pagerduty — Events API v2 (routing key in webhook.pagerduty.routingKey)
	//   feishu    — custom robot text message
	//   wecom     — enterprise WeChat group robot text message
	//   dingtalk  — DingTalk group robot text message
	//   slack     — incoming webhook JSON (text)
	NotifyFormat string `yaml:"notifyFormat,omitempty"`

	// PagerDuty is read only when notifyFormat=pagerduty.
	PagerDuty PagerDutyNotify `yaml:"pagerduty,omitempty"`

	// Jira is read only when notifyFormat=jira.
	Jira JiraNotify `yaml:"jira,omitempty"`
	// NotifySecretFile is the file variant of NotifySecret, exactly like TokenFile.
	NotifySecretFile string `yaml:"notifySecretFile,omitempty"`
}

// JiraNotify points at a Jira Server/Data Center or Cloud REST API and names the
// issue to create. Field names are configurable on purpose: every team's project
// uses a different issue type and label set, and a hardcoded one becomes a fork.
type JiraNotify struct {
	// BaseURL is the Jira origin (https://jira.example.com). notifyURL is NOT reused
	// for this format: one is a webhook receiver, the other is a REST API root.
	BaseURL string `yaml:"baseURL"`

	// ProjectKey and IssueType are the issue to create (e.g. OPS / Bug / Incident).
	ProjectKey string `yaml:"projectKey"`
	IssueType  string `yaml:"issueType"`

	// Email + APIToken is Jira Cloud's basic auth (email + API token). APITokenFile
	// is preferred so the secret stays out of config.yaml.
	Email        string `yaml:"email,omitempty"`
	APIToken     string `yaml:"apiToken,omitempty"`
	APITokenFile string `yaml:"apiTokenFile,omitempty"`

	// Auth selects the Authorization header: "basic" (email:apiToken, Jira Cloud API
	// tokens and Server PATs) or "bearer" (a raw PAT/OAuth access token). Default basic.
	Auth string `yaml:"auth,omitempty"`

	// Labels are added to every created issue. wecert always adds "wecert" and
	// "wecert-cert-<name>" so a second failure for the same certificate can find the
	// open issue instead of opening another.
	Labels []string `yaml:"labels,omitempty"`

	// ReuseOpenIssue finds an open issue with the wecert-cert-<name> label and
	// comments on it instead of creating a duplicate. Default true when the field is
	// unset -- a new ticket every failed renewal is how an integration gets ignored.
	ReuseOpenIssue *bool `yaml:"reuseOpenIssue,omitempty"`
}

// Jira auth modes.
const (
	JiraAuthBasic  = "basic"
	JiraAuthBearer = "bearer"
)

// PagerDutyNotify is the Events API v2 routing key. The URL is still
// webhook.notifyURL (https://events.pagerduty.com/v2/enqueue).
type PagerDutyNotify struct {
	// RoutingKey is the integration key of the PagerDuty service. Required for
	// notifyFormat=pagerduty. Prefer an environment-expanded file over inlining it.
	RoutingKey     string `yaml:"routingKey,omitempty"`
	RoutingKeyFile string `yaml:"routingKeyFile,omitempty"`
}

// Notify format names.
const (
	NotifyFormatGeneric   = "generic"
	NotifyFormatPagerDuty = "pagerduty"
	NotifyFormatFeishu    = "feishu"
	NotifyFormatWeCom     = "wecom"
	NotifyFormatDingTalk  = "dingtalk"
	NotifyFormatSlack     = "slack"
	NotifyFormatJira      = "jira"
)

// WebhookAdminTokenMinLen is the minimum admin token length. Longer than the
// read-only token's floor: this one can restore state.
const WebhookAdminTokenMinLen = 32

// WebhookTokenMinLen is the minimum token length.
// A short token is no authentication at all on this endpoint — an attacker who
// triggers issuance can burn the rate-limit quota.
const WebhookTokenMinLen = 16

// WebhookNotifySecretMinLen is the minimum HMAC secret length.
// An HMAC key shorter than its hash's output can be recovered by brute force from
// a single signed event, so a short secret gives a false sense of authenticity.
const WebhookNotifySecretMinLen = 32
