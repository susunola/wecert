package acme

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A cancellation that lands during the recursive probe must surface as a cancellation, not as
// "propagated".
//
// recursiveReady degrades "no resolver answered" to a warning, because a host without public
// DNS egress must still be able to issue. A cancelled context makes every resolver unreachable,
// so the same fallback fired for a shutdown: waitZone logged "TXT propagated" and returned nil,
// and upstream a cancelled pass booked a success it never verified.
func TestCancellationDuringTheRecursiveProbeIsNotAPropagationSuccess(t *testing.T) {
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	solver := &DNSSolver{
		recursiveNameservers: []string{"192.0.2.53:53"},
		log:                  slog.New(slog.NewTextHandler(&logs, nil)),
		interval:             time.Millisecond,
		timeout:              5 * time.Second,
		exchange: func(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == "192.0.2.53:53" {
				// The shutdown lands while the recursive probe is in flight: cancel, then
				// answer the way a dead context does. The authoritative probes run under
				// their own context (see authoritativeExchange) and are unaffected.
				cancel()
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return authoritativeTXT(msg, "wanted"), nil
		},
	}
	recs := []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}}

	err := solver.waitZone(ctx, "example.com.", recursiveTestServers(), 2, recs,
		recursiveTestBudget(5*time.Second))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled wait must report the cancellation, got: %v", err)
	}
	if strings.Contains(logs.String(), "TXT propagated") {
		t.Error("the success line must not be logged for a verdict a shutdown cut short")
	}
}
