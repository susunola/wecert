package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotificationSaveRedactsSecrets(t *testing.T) {
	old := configPathForAdmin
	defer func() { configPathForAdmin = old }()
	configPathForAdmin = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPathForAdmin, []byte("certificates: []\nwebhook:\n  token: unchanged\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := notificationSettings(context.Background(), http.MethodPut, map[string]any{"format": "wecom", "url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=secret-test-value"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := notificationSettings(context.Background(), http.MethodGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.(map[string]any)["target"].(string), "secret-test-value") {
		t.Fatal("secret leaked")
	}
	data, _ := os.ReadFile(configPathForAdmin)
	if !strings.Contains(string(data), "token: unchanged") {
		t.Fatal("unrelated config changed")
	}
	info, _ := os.Stat(configPathForAdmin)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
}

func TestRobotURLValidation(t *testing.T) {
	for _, raw := range []string{"http://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x", "https://localhost/x", "https://qyapi.weixin.qq.com.evil.test/cgi-bin/webhook/send?key=x", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send"} {
		if validateRobot("wecom", raw) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if err := validateRobot("wecom", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test"); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveCertificatePreservesFollowingSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := "certificates:\n  - name: 'legacy'\n    domains: [legacy.example.com]\nwebhook:\n  listen: ':9801'\n"
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeCertificateFromConfig(path, "legacy"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "webhook:") || strings.Contains(string(data), "legacy") {
		t.Fatalf("bad configuration: %s", data)
	}
}
