package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/acme"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// runRevoke implements -revoke: record the operator's decision, then ask the CA.
//
// The order matters and is the whole reason this is not just a single API call. The request is
// written to the state store FIRST, so a transient CA failure leaves a durable record and the
// daemon's next pass retries it. Doing the API call first would mean a timeout left the
// operator believing a compromised certificate was revoked when it was not -- for this
// particular action, the most dangerous way to be wrong.
//
// It reuses the daemon's own config and state so there is one source of truth for the ACME
// account: revocation is authenticated with the same account key that issued the certificate,
// and being a separate binary must not mean a second copy of that key.
func runRevoke(configPath, statePathOverride, certName, reasonName string, assumeYes bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if statePathOverride != "" {
		cfg.StatePath = statePathOverride
	}

	reason, ok := acme.RevocationReasons[reasonName]
	if !ok {
		return fmt.Errorf("unknown -revoke-reason %q; expected one of %s",
			reasonName, strings.Join(reasonNames(), "|"))
	}

	// Confirmation, because this cannot be undone: a revoked certificate is dead for every
	// client immediately, and the only fix is to issue a new one.
	if !assumeYes {
		fmt.Fprintf(os.Stderr, "Revoke certificate %q (reason: %s)?\n"+
			"This takes effect immediately and cannot be undone.\n"+
			"Type the certificate name to confirm: ", certName, reasonName)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(answer) != certName {
			return fmt.Errorf("not confirmed; nothing was revoked")
		}
	}

	// The daemon holds the state lock, and "cannot revoke because the daemon is running" is the
	// wrong answer for a security action. The unlocked open is the same one -dry-run uses: this
	// path reads the account key and writes one row, and initiates no issuance.
	// OpenForTool, not OpenUnlocked: the daemon usually holds the lock (this is the command an
	// operator runs while it is up), but if it does not, taking the lock means a schema that is
	// behind gets migrated instead of the revocation failing.
	store, err := state.OpenForTool(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("open the state store: %w", err)
	}
	defer store.Close()

	// The same account the daemon issues with: revocation is authenticated with the account key
	// that placed the order, and being a separate invocation must not mean a second copy of it.
	// EnsureAccount is idempotent -- an account already in the store is loaded, not replaced.
	log := newLogger("info")
	core, err := acme.EnsureAccount(cfg, store, acme.NewHTTPClient(60*time.Second))
	if err != nil {
		return fmt.Errorf("prepare the ACME account: %w", err)
	}

	// A manager with no solver and no deployer: revocation needs neither, and passing nil keeps
	// it obvious that this path cannot issue or deploy anything.
	m := acme.NewManager(store, acme.NewAPI(core), nil, nil, log)
	if err := m.RequestRevocation(context.Background(), certName, reason); err != nil {
		// The request is recorded regardless, so this is reported as "not yet", not "failed".
		fmt.Fprintf(os.Stderr, "\nNOT YET REVOKED: %v\n", err)
		fmt.Fprintf(os.Stderr, "The request is recorded in %s and will be retried on every pass.\n",
			cfg.StatePath)
		return err
	}

	fmt.Printf("Revoked %q (reason: %s).\n", certName, reasonName)
	return nil
}

func reasonNames() []string {
	out := make([]string, 0, len(acme.RevocationReasons))
	for _, n := range []string{"unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation"} {
		if _, ok := acme.RevocationReasons[n]; ok {
			out = append(out, n)
		}
	}
	return out
}
