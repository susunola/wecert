package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// newCloudflareTXTRecovery supplies the one operation lego cannot perform after
// restart: its provider stores record IDs only in an in-memory token map. We list
// and delete only the exact FQDN/value pair, never every TXT at the name, so a
// wildcard or another certificate sharing _acme-challenge remains intact.
func newCloudflareTXTRecovery(token, tokenFile string) func(context.Context, string, DNSRecord) error {
	return func(ctx context.Context, zone string, rec DNSRecord) error {
		if tokenFile != "" {
			token = rereadSecretFile(tokenFile, token)
		}
		if token == "" {
			return fmt.Errorf("Cloudflare API token is empty")
		}
		client := &http.Client{Timeout: dnsAPITimeout}
		zoneID, err := cloudflareZoneID(ctx, client, token, strings.TrimSuffix(zone, "."))
		if err != nil {
			return err
		}
		return cloudflareDeleteExactTXT(ctx, client, token, zoneID, rec)
	}
}

type cloudflareResponse[T any] struct {
	Success bool `json:"success"`
	Result  T    `json:"result"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type cloudflareZone struct {
	ID string `json:"id"`
}
type cloudflareTXTRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func cloudflareZoneID(ctx context.Context, client *http.Client, token, zone string) (string, error) {
	q := url.Values{"name": {zone}, "per_page": {"2"}}
	var out cloudflareResponse[[]cloudflareZone]
	if err := cloudflareRequest(ctx, client, token, http.MethodGet, "https://api.cloudflare.com/client/v4/zones?"+q.Encode(), &out); err != nil {
		return "", err
	}
	if len(out.Result) != 1 || out.Result[0].ID == "" {
		return "", fmt.Errorf("Cloudflare zone %q was not found uniquely", zone)
	}
	return out.Result[0].ID, nil
}

func cloudflareDeleteExactTXT(ctx context.Context, client *http.Client, token, zoneID string, rec DNSRecord) error {
	q := url.Values{"type": {"TXT"}, "name": {strings.TrimSuffix(rec.FQDN, ".")}, "per_page": {"100"}}
	var listed cloudflareResponse[[]cloudflareTXTRecord]
	if err := cloudflareRequest(ctx, client, token, http.MethodGet, "https://api.cloudflare.com/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records?"+q.Encode(), &listed); err != nil {
		return err
	}
	for _, record := range listed.Result {
		if record.Type != "TXT" || strings.TrimSuffix(record.Name, ".") != strings.TrimSuffix(rec.FQDN, ".") || strings.Trim(record.Content, "\"") != rec.Value {
			continue
		}
		if err := cloudflareRequest(ctx, client, token, http.MethodDelete, "https://api.cloudflare.com/client/v4/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(record.ID), nil); err != nil {
			return err
		}
	}
	return nil
}

func cloudflareRequest(ctx context.Context, client *http.Client, token, method, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare API returned HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return nil
}
