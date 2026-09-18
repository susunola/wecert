package acme

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// Setting LEGO_DEBUG_DNS_API_HTTP_CLIENT on a dnspod deployment must produce a loud warning.
//
// lego wraps the provider's HTTP client in its debug dumper, which redacts credential HEADERS --
// but dnspod-go sends the credential in the POST body as login_token=..., and a DNSPod-native
// token never expires. On a service that means the token lands in the journal; the warning is
// the only chance to catch that before it happens.
func TestDNSPodSolverWarnsAboutTheDebugHTTPClientVariable(t *testing.T) {
	t.Setenv("LEGO_DEBUG_DNS_API_HTTP_CLIENT", "true")

	var logs bytes.Buffer
	_, err := NewDNSSolver(config.DNS{
		Provider:             config.DNSProviderDNSPod,
		LoginToken:           "12345,token",
		RecursiveNameservers: []string{"192.0.2.53:53"},
		Propagation:          time.Minute,
		Polling:              time.Second,
	}, config.Tencent{}, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("a valid dnspod configuration must build: %v", err)
	}
	if !strings.Contains(logs.String(), "LEGO_DEBUG_DNS_API_HTTP_CLIENT") {
		t.Errorf("the variable leaks a never-expiring credential into the log; the warning naming "+
			"it is missing from:\n%s", logs.String())
	}
}
