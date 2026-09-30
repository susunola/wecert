package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/atomicfile"
	"github.com/susunola/wecert/internal/webhook"
	"gopkg.in/yaml.v3"
)

// configMu serialises every writer of config.yaml and its registry sidecars:
// certificate create/delete, DNS credential wiring, account add/remove, and
// notification settings. One mutex, one file family, no lost updates.
var configMu sync.Mutex

// Only documented robot endpoints are accepted here, not arbitrary SSRF targets.
func validateRobot(format, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return fmt.Errorf("use an HTTPS robot URL without credentials, port or fragment")
	}
	hosts := map[string]string{"wecom": "qyapi.weixin.qq.com", "feishu": "open.feishu.cn", "dingtalk": "oapi.dingtalk.com"}
	paths := map[string]string{"wecom": "/cgi-bin/webhook/send", "feishu": "/open-apis/bot/v2/hook/", "dingtalk": "/robot/send"}
	if hosts[format] == "" || u.Hostname() != hosts[format] {
		return fmt.Errorf("robot URL does not match the selected channel")
	}
	if format == "feishu" {
		if !strings.HasPrefix(u.Path, paths[format]) || len(strings.TrimPrefix(u.Path, paths[format])) < 10 {
			return fmt.Errorf("invalid Feishu robot path")
		}
	} else if u.Path != paths[format] {
		return fmt.Errorf("invalid robot path")
	}
	if format == "wecom" && u.Query().Get("key") == "" || format == "dingtalk" && u.Query().Get("access_token") == "" {
		return fmt.Errorf("robot URL is missing its token")
	}
	return nil
}

// yamlFind returns the value node for key in a mapping, or nil when absent.
// Read-only: it never mutates the document.
func yamlFind(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// yamlGetOrCreate returns the value node for key, inserting an empty scalar when
// it is missing. Only writers that are about to fill the node use this.
func yamlGetOrCreate(n *yaml.Node, key string) *yaml.Node {
	if found := yamlFind(n, key); found != nil {
		return found
	}
	value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
	return value
}

func notificationSettings(ctx context.Context, method string, body map[string]any) (any, error) {
	configMu.Lock()
	defer configMu.Unlock()
	raw, err := os.ReadFile(configPathForAdmin)
	if err != nil {
		return nil, fmt.Errorf("cannot read daemon configuration")
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid daemon configuration")
	}
	section := yamlGetOrCreate(doc.Content[0], "webhook")
	if section.Kind == yaml.ScalarNode && section.Value == "" {
		section.Kind = yaml.MappingNode
		section.Tag = "!!map"
	}
	if section.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("webhook must be a mapping")
	}
	target := yamlGetOrCreate(section, "notifyURL")
	format := yamlGetOrCreate(section, "notifyFormat")
	if method == http.MethodGet {
		return map[string]any{"configured": target.Value != "", "format": format.Value, "target": webhook.RedactNotifyURL(target.Value)}, nil
	}
	nextURL, _ := body["url"].(string)
	nextFormat, _ := body["format"].(string)
	if nextURL == "" {
		nextURL = target.Value
	}
	if err = validateRobot(nextFormat, nextURL); err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		return testRobot(ctx, nextFormat, nextURL)
	}
	// Preserve YAML structure/comments and all unrelated settings. Secrets are 0600.
	target.Value = nextURL
	target.Tag = "!!str"
	format.Value = nextFormat
	format.Tag = "!!str"
	updated, err := encodeYAML(&doc)
	if err != nil {
		return nil, fmt.Errorf("cannot encode configuration")
	}
	if err = atomicfile.Write(configPathForAdmin, updated, 0600); err != nil {
		return nil, fmt.Errorf("cannot save configuration")
	}
	// Deliberately report saved != active: operator reload uses the existing admission gate.
	return map[string]any{"saved": true, "restartRequired": true, "note": "Saved. Reload or restart the daemon to activate; test delivery is available immediately."}, nil
}

func testRobot(ctx context.Context, format, target string) (any, error) {
	payload := map[string]any{"msgtype": "text", "text": map[string]string{"content": "[WeCert] Test notification — channel connectivity check."}}
	if format == "feishu" {
		payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": "[WeCert] Test notification — channel connectivity check."}}
	}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("invalid notification request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notification connection failed; check URL and network")
	}
	defer resp.Body.Close()
	var reply struct {
		Errcode    *int `json:"errcode"`
		Code       *int `json:"code"`
		StatusCode *int `json:"StatusCode"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&reply)
	success := reply.Errcode != nil && *reply.Errcode == 0
	if format == "feishu" {
		success = reply.Code != nil && *reply.Code == 0 || reply.StatusCode != nil && *reply.StatusCode == 0
	}
	if err != nil || resp.StatusCode != 200 || !success {
		return nil, fmt.Errorf("robot rejected test delivery; check robot configuration")
	}
	return map[string]any{"delivered": true, "time": time.Now().UTC().Format(time.RFC3339)}, nil
}

// encodeYAML renders a document with the conventional 2-space indent.
// yaml.Marshal's default is 4, so using it to round-trip a file rewrites every
// nested block and hides real changes in a formatting diff.
func encodeYAML(node *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(node); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
