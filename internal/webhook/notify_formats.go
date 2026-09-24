package webhook

import (
	"encoding/json"
	"fmt"
	"github.com/susunola/wecert/internal/config"
)

// notifyPayload is the POST body for one renewal event in the selected product's
// wire format. generic is the only one that is a stable public contract (and the
// only one X-Wecert-Signature is defined over); the rest are thin adapters so a
// chat robot or PagerDuty can receive the event without a translator in front.
//
// Severity mapping: result=error is an alert (PagerDuty trigger / red text);
// result=ok is informational (PagerDuty is NOT triggered -- a green tick in the
// on-call channel every night is how an integration gets muted).
func (n *Notifier) notifyPayload(ev RenewalEvent) ([]byte, error) {
	switch n.format {
	case config.NotifyFormatPagerDuty:
		return n.pagerdutyPayload(ev)
	case config.NotifyFormatFeishu:
		return json.Marshal(map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": notifyLine(ev)},
		})
	case config.NotifyFormatWeCom:
		return json.Marshal(map[string]any{
			"msgtype": "text",
			"text":    map[string]string{"content": notifyLine(ev)},
		})
	case config.NotifyFormatDingTalk:
		return json.Marshal(map[string]any{
			"msgtype": "text",
			"text":    map[string]string{"content": notifyLine(ev)},
		})
	case config.NotifyFormatSlack:
		// Incoming webhook: {"text": "..."} is enough and works on every Slack-compatible
		// endpoint. Blocks would look nicer and tie the adapter to one API version.
		return json.Marshal(map[string]any{"text": notifyLine(ev)})
	default:
		return json.Marshal(ev)
	}
}

// notifyLine is the one-sentence form the chat products all accept.
func notifyLine(ev RenewalEvent) string {
	if ev.Result == "error" {
		return fmt.Sprintf("[wecert] %s renewal FAILED (%s): %s", ev.Cert, ev.Timestamp, ev.Error)
	}
	return fmt.Sprintf("[wecert] %s renewed OK (%s)", ev.Cert, ev.Timestamp)
}

// pagerdutyPayload builds an Events API v2 envelope.
//
// dedupKey is the certificate name so a second failure for the same certificate
// updates the open incident instead of paging again -- PagerDuty's own guidance
// for "this resource is unhealthy". action is trigger only for errors: a
// successful renewal is not an on-call event (see notifyPayload).
func (n *Notifier) pagerdutyPayload(ev RenewalEvent) ([]byte, error) {
	if n.pdRoutingKey == "" {
		return nil, fmt.Errorf("pagerduty routing key is empty")
	}
	action := "trigger"
	severity := "error"
	source := ev.Cert
	summary := fmt.Sprintf("wecert: %s renewal failed", ev.Cert)
	if ev.Result != "error" {
		// Resolve the open incident for this certificate (dedup_key). A success that
		// never triggered is a no-op resolve -- PagerDuty accepts it and it does not
		// page. Without this, fail->ok left the on-call incident open forever.
		return json.Marshal(map[string]any{
			"routing_key":  n.pdRoutingKey,
			"event_action": "resolve",
			"dedup_key":    "wecert/" + ev.Cert,
			"payload": map[string]any{
				"summary": fmt.Sprintf("wecert: %s renewed", ev.Cert),
				"source":  ev.Cert,
			},
		})
	}
	payload := map[string]any{
		"routing_key":  n.pdRoutingKey,
		"event_action": action,
		"dedup_key":    "wecert/" + ev.Cert,
		"payload": map[string]any{
			"summary":   summary,
			"source":    source,
			"severity":  severity,
			"timestamp": ev.Timestamp,
			"custom_details": map[string]any{
				"event":  ev.Event,
				"cert":   ev.Cert,
				"result": ev.Result,
				"error":  ev.Error,
			},
		},
	}
	return json.Marshal(payload)
}

// errSkipPagerDutySuccess means "not an incident": send() logs at Debug and
// returns without treating it as a delivery failure.
var errSkipPagerDutySuccess = fmt.Errorf("pagerduty: success renewals do not page")
