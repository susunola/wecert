// Command wecert is a cert-manager-style ACME certificate renewal daemon, built for
// deployments where TLS terminates at a Tencent Cloud CLB and the CVM fleet only runs
// the business workload.
//
// Because decryption happens at the CLB, the system needs no node agent and no
// certificate files have to be distributed: one machine, one binary, one SQLite file.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/susunola/wecert/internal/acme"
)

// version can be injected through -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// The ACME User-Agent names the running build, so a CA-side log lines up with the binary that
	// sent the request. It is set here, at process start, rather than inside run(): run() returns
	// from the -revoke branch early, and having the call after that branch meant every revocation
	// -- the request an operator makes about a compromised key -- identified itself as "wecert/dev".
	// A global with no dependencies belongs at the top, where no branch can skip it.
	acme.SetUserAgentVersion(version)

	if err := run(); err != nil {
		// exitUsage is the conventional "the command line itself is wrong" code, the same one
		// wecert-onboard and wecert-probe use -- and it matters here because the alternative was
		// flag.ExitOnError's 2, which this repository documents as wecert-onboard's "deliberately
		// frozen, a human should look" code. A typo in wecert-once.service's ExecStart is not a
		// freeze, and a monitoring rule keyed on 2 must not read it as one.
		if errors.Is(err, errUsage) {
			// A bare errUsage carries nothing to print: the flag package has already printed
			// the offending flag and the usage. An error that only WRAPS it (a contradictory
			// flag combination, an unknown -log-level, a -restore conflict) carries its own
			// sentence, which used to be discarded right here -- the message existed and the
			// operator never saw it.
			if msg := usageExitMessage(err); msg != "" {
				fmt.Fprintf(os.Stderr, "wecert: %v\n", msg)
			}
			os.Exit(exitUsage)
		}
		slog.Error("wecert exited with an error", "err", err)
		os.Exit(1)
	}
}

// usageExitMessage is what main prints for a command-line error before exiting 64: nothing for
// a bare errUsage (the flag package has already printed the offending flag and the usage), the
// message itself for anything wrapping it -- validateFlags' contradictions, an unknown
// -log-level, errRestoreConflict. Those sentences used to be discarded on the way to the exit
// code, so a contradictory command line produced a silent exit 64.
func usageExitMessage(err error) string {
	if err == errUsage {
		return ""
	}
	return err.Error()
}

func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", level)
}

func newLogger(level slog.Level) *slog.Logger {
	// Without timestamps it reads better under systemd/journald; in a terminal they help.
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
