package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
//
// The ctx is the process's signal context: main installs it before this runs precisely so a
// SIGTERM during revocation takes the graceful path, and passing context.Background() here
// silently dropped that promise -- the comment at the signal installation said this path was
// covered, and it was not.
func runRevoke(ctx context.Context, configPath, statePathOverride, certName, reasonName string, assumeYes bool) error {
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
	// Sealed deployments have to be opened the way the daemon opens them. Opening without the sealer
	// hands the caller sealed blobs as if they were plaintext, so the one command an operator runs
	// about a leaked key failed on exactly the deployments that had done the most to protect it --
	// with a PEM parse error, since that is what the ciphertext looks like to a PEM decoder.
	openStore := state.OpenForTool
	if cfg.StateEncryption.Key != "" {
		openStore = func(path string) (*state.Store, error) {
			return state.OpenSealedForTool(path, []byte(cfg.StateEncryption.Key))
		}
	}
	store, err := openStore(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("open the state store: %w", err)
	}
	defer store.Close()

	log := newLogger(slog.LevelInfo)

	// Record the decision BEFORE reading the CA directory, with a manager that has no CA core at all.
	//
	// This is the documented promise -- "the request is written to the state store FIRST, so a
	// transient CA failure leaves a durable record and the daemon's next pass retries it" -- and it
	// was not true: EnsureAccount came first, so a CA directory that was unreachable (or a network
	// that was down) made the command fail with nothing recorded, no retry, and
	// wecert_revocation_pending at 0, on the one action an operator takes about a leaked key.
	if err := acme.NewManager(store, nil, nil, nil, log).RecordRevocation(certName, reason); err != nil {
		return err
	}

	// The same account the daemon issues with: revocation is authenticated with the account key
	// that placed the order, and being a separate invocation must not mean a second copy of it.
	// EnsureAccount is idempotent -- an account already in the store is loaded, not replaced.
	core, err := acme.EnsureAccount(cfg, store, acme.NewHTTPClient(60*time.Second))
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nNOT YET REVOKED: %v\n", err)
		fmt.Fprintf(os.Stderr, "The request IS recorded in %s and will be retried on every pass, so the "+
			"daemon will revoke it as soon as the CA is reachable. Fix the reason above (or start the "+
			"daemon) and it will complete on its own.\n", cfg.StatePath)
		return fmt.Errorf("prepare the ACME account: %w", err)
	}

	// A manager with no solver and no deployer: revocation needs neither, and passing nil keeps
	// it obvious that this path cannot issue or deploy anything.
	m := acme.NewManager(store, acme.NewAPI(core), nil, nil, log)
	if err := m.AttemptRecordedRevocation(ctx, certName); err != nil {
		fmt.Fprintf(os.Stderr, "\nNOT YET REVOKED: %v\n", err)
		// The record was written before EnsureAccount ran, so by this point the request is durable and
		// the daemon's next pass retries it. (The ErrRevocationNotRecorded branch that used to be here
		// belongs to the recording step above, which has already returned by now.)
		if errors.Is(err, acme.ErrRevocationNotRecorded) {
			fmt.Fprintf(os.Stderr, "Nothing was recorded, so nothing will retry this on its own: fix the "+
				"reason above and run the command again.\n")
		} else {
			fmt.Fprintf(os.Stderr, "The request is recorded in %s and will be retried on every pass.\n",
				cfg.StatePath)
		}
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
