package webhook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// deliverJira turns one renewal event into a Jira issue (or a comment on the open
// issue for that certificate).
//
// Why search-before-create: a certificate that fails every hour would otherwise
// open a ticket an hour and the board becomes noise. The labels wecert and
// wecert-cert-<name> are the join key; ReuseOpenIssue is on by default.
//
// API v2 (not v3) so the description is a plain string -- Jira Cloud accepts v2
// and so does Server/DC, which is what most on-prem wecert deployments will have.
func (n *Notifier) deliverJira(ctx context.Context, ev RenewalEvent) error {
	if n.jira.BaseURL == "" {
		return fmt.Errorf("jira: baseURL is empty")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if ev.Result != "error" {
		// Close the loop: comment on the open issue (if any) that this certificate
		// recovered. Without it the ticket stays open after the fix, like PagerDuty
		// never resolving. No issue is created for a green renewal.
		if !n.jira.ReuseOpenIssue {
			return nil
		}
		labels := jiraLabels(n.jira.Labels, ev.Cert)
		key, err := n.jiraFindOpen(ctx, labels)
		if err != nil || key == "" {
			return err
		}
		return n.jiraComment(ctx, key, "wecert: "+ev.Cert+" renewed OK at "+ev.Timestamp+".")
	}

	labels := jiraLabels(n.jira.Labels, ev.Cert)
	if n.jira.ReuseOpenIssue {
		key, err := n.jiraFindOpen(ctx, labels)
		if err != nil {
			return err
		}
		if key != "" {
			return n.jiraComment(ctx, key, jiraDescription(ev))
		}
	}
	return n.jiraCreate(ctx, ev, labels)
}

func jiraLabels(extra []string, certName string) []string {
	out := append([]string(nil), extra...)
	out = append(out, "wecert", "wecert-cert-"+jiraLabel(certName))
	return out
}

// jiraLabel makes a certificate name safe as a Jira label (no spaces, lower case).
func jiraLabel(name string) string {
	// A wildcard certificate's name starts with "*." -- the star is not a character
	// a label can carry, and "example.com" is the useful join key anyway.
	name = strings.TrimPrefix(name, "*.")
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "unnamed"
	}
	return s
}

func jiraSummary(ev RenewalEvent) string {
	return fmt.Sprintf("wecert: %s renewal failed", ev.Cert)
}

func jiraDescription(ev RenewalEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "wecert reported a failed renewal.\n\n")
	fmt.Fprintf(&b, "Certificate: %s\n", ev.Cert)
	fmt.Fprintf(&b, "Result:      %s\n", ev.Result)
	if ev.Error != "" {
		fmt.Fprintf(&b, "Error:       %s\n", ev.Error)
	}
	fmt.Fprintf(&b, "Timestamp:   %s\n", ev.Timestamp)
	fmt.Fprintf(&b, "\nEvent:       %s\n", ev.Event)
	return b.String()
}

func (n *Notifier) jiraFindOpen(ctx context.Context, labels []string) (string, error) {
	jql := fmt.Sprintf(`labels = "%s" AND labels = "wecert" AND statusCategory != Done ORDER BY created DESC`,
		jiraLabel(strings.TrimPrefix(findWecertCertLabel(labels), "wecert-cert-")))
	// Prefer the dedicated cert label when present.
	for _, l := range labels {
		if strings.HasPrefix(l, "wecert-cert-") {
			jql = fmt.Sprintf(`labels = "%s" AND statusCategory != Done ORDER BY created DESC`, l)
			break
		}
	}
	body, err := json.Marshal(map[string]any{
		"jql":        jql,
		"maxResults": 1,
		"fields":     []string{"key", "summary"},
	})
	if err != nil {
		return "", err
	}
	resp, err := n.jiraDo(ctx, http.MethodPost, "/rest/api/2/search", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// A failed search must not silently create a duplicate: say so and let the
		// caller retry next event. The board stays clean at the cost of one missed
		// comment.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("jira search %s: status %d: %s", jql, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("jira search decode: %w", err)
	}
	if len(out.Issues) == 0 {
		return "", nil
	}
	return out.Issues[0].Key, nil
}

func findWecertCertLabel(labels []string) string {
	for _, l := range labels {
		if strings.HasPrefix(l, "wecert-cert-") {
			return l
		}
	}
	return ""
}

func (n *Notifier) jiraCreate(ctx context.Context, ev RenewalEvent, labels []string) error {
	body, err := json.Marshal(map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": n.jira.ProjectKey},
			"issuetype":   map[string]string{"name": n.jira.IssueType},
			"summary":     jiraSummary(ev),
			"description": jiraDescription(ev),
			"labels":      labels,
		},
	})
	if err != nil {
		return err
	}
	resp, err := n.jiraDo(ctx, http.MethodPost, "/rest/api/2/issue", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("jira create issue: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Key string `json:"key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	n.log.Info("jira issue created", "cert", ev.Cert, "key", out.Key)
	return nil
}

func (n *Notifier) jiraComment(ctx context.Context, key, bodyText string) error {
	body, err := json.Marshal(map[string]any{"body": bodyText})
	if err != nil {
		return err
	}
	resp, err := n.jiraDo(ctx, http.MethodPost, "/rest/api/2/issue/"+url.PathEscape(key)+"/comment", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("jira comment on %s: status %d: %s", key, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	n.log.Info("jira issue commented", "key", key)
	return nil
}

func (n *Notifier) jiraDo(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	base := strings.TrimRight(n.jira.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	switch n.jira.Auth {
	case config.JiraAuthBearer:
		req.Header.Set("Authorization", "Bearer "+n.jira.APIToken)
	default:
		cred := base64.StdEncoding.EncodeToString([]byte(n.jira.Email + ":" + n.jira.APIToken))
		req.Header.Set("Authorization", "Basic "+cred)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, withoutURL(err)
	}
	return resp, nil
}
