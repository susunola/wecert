package webhook

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
)

func formatNotifier(format, pdKey string) *Notifier {
	return NewNotifierFormat("http://example.invalid/hook", "secret-32-characters-long-enough", format, pdKey,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestNotifyPayloadShapes(t *testing.T) {
	fail := RenewalEvent{Event: "renewal", Cert: "www", Result: "error", Error: "boom", Timestamp: "2026-09-24T00:00:00Z"}
	ok := RenewalEvent{Event: "renewal", Cert: "www", Result: "ok", Timestamp: "2026-09-24T00:00:00Z"}

	// generic: the documented JSON event
	b, err := formatNotifier(config.NotifyFormatGeneric, "").notifyPayload(fail)
	if err != nil {
		t.Fatal(err)
	}
	var ev RenewalEvent
	if err := json.Unmarshal(b, &ev); err != nil || ev.Cert != "www" || ev.Result != "error" {
		t.Fatalf("generic payload %s", b)
	}

	// feishu / wecom / dingtalk / slack: one text line
	for _, format := range []string{config.NotifyFormatFeishu, config.NotifyFormatWeCom, config.NotifyFormatDingTalk, config.NotifyFormatSlack} {
		b, err := formatNotifier(format, "").notifyPayload(fail)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !strings.Contains(string(b), "renewal FAILED") || !strings.Contains(string(b), "boom") {
			t.Errorf("%s payload must name the failure, got %s", format, b)
		}
	}

	// pagerduty: trigger only on failure
	b, err = formatNotifier(config.NotifyFormatPagerDuty, "R0-routing").notifyPayload(fail)
	if err != nil {
		t.Fatal(err)
	}
	var pd map[string]any
	if err := json.Unmarshal(b, &pd); err != nil {
		t.Fatal(err)
	}
	if pd["event_action"] != "trigger" || pd["dedup_key"] != "wecert/www" {
		t.Fatalf("pagerduty envelope %s", b)
	}
	if !strings.Contains(string(b), "R0-routing") {
		t.Error("routing key must be in the body")
	}

	// success resolves the open incident (it does not page)
	b, err = formatNotifier(config.NotifyFormatPagerDuty, "R0").notifyPayload(ok)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &pd); err != nil {
		t.Fatal(err)
	}
	if pd["event_action"] != "resolve" {
		t.Fatalf("success must resolve, got %s", b)
	}
}
