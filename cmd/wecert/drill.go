package main

import (
	"fmt"
	"os"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// runBackupDrill is deliberately read-only: it exercises the same source
// resolution and SQLite integrity check as restore, but never obtains the live
// database lock or moves a file. It is safe for scheduled recovery evidence.
func runBackupDrill(configPath, statePathOverride, arg string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if statePathOverride != "" {
		cfg.StatePath = statePathOverride
	}
	source, cleanup, err := resolveRestoreSnapshot(cfg, arg)
	if err != nil {
		return err
	}
	defer cleanup()
	info, err := state.InspectSnapshot(source)
	if err != nil {
		return fmt.Errorf("backup drill failed: %w", err)
	}
	fi, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat checked snapshot: %w", err)
	}
	fmt.Printf("Backup drill passed: %s holds %s and %d certificate(s); snapshot age %s. No live state was changed.\n", source, accountPhrase(info.Account), info.Certificates, time.Since(fi.ModTime()).Round(time.Second))
	return nil
}
