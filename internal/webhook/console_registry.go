package webhook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/susunola/wecert/internal/atomicfile"
)

// ConsoleCertificate is one row of the console-certificates.json sidecar the
// web console writes beside the state database. Typed so the reader never has
// to coerce a JSON value through fmt.Sprint and special-case "<nil>".
type ConsoleCertificate struct {
	Name    string         `json:"name"`
	Domains []string       `json:"domains"`
	Profile string         `json:"profile"`
	KeyType string         `json:"keyType"`
	UIN     string         `json:"uin"`
	DNS     *DNSCredential `json:"dns,omitempty"`
}

// CloudAccount is one row of cloud-accounts.json.
type CloudAccount struct {
	Name  string `json:"name"`
	UIN   string `json:"uin"`
	Cred  string `json:"cred"`
	Cloud string `json:"cloud"`
	// Site is "china", "international", or "" (auto).
	Site    string `json:"site,omitempty"`
	KeyPath string `json:"keyPath"`
}

// readRegistry loads a JSON array. A corrupt file is an error, never a silent
// empty list: treating it as empty is what turns one bad byte into the loss of
// every recorded row on the next write.
func readRegistry[T any](path string) ([]T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []T{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return []T{}, nil
	}
	var list []T
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("registry %s is not valid JSON (refusing to overwrite it): %w", path, err)
	}
	if list == nil {
		list = []T{}
	}
	return list, nil
}

// writeRegistry always emits a JSON array (json.MarshalIndent of a nil slice is
// "null", which the next Unmarshal leaves as a nil list).
func writeRegistry[T any](path string, list []T) error {
	if list == nil {
		list = []T{}
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// ReadConsoleCertificates is the read side of the console sidecar.
func ReadConsoleCertificates(statePath string) ([]ConsoleCertificate, error) {
	return readRegistry[ConsoleCertificate](consoleRegistryPath(statePath))
}

// WriteConsoleCertificates replaces the console sidecar.
func WriteConsoleCertificates(statePath string, list []ConsoleCertificate) error {
	return writeRegistry(consoleRegistryPath(statePath), list)
}

// ReadCloudAccounts / WriteCloudAccounts own the account sidecar.
func ReadCloudAccounts(statePath string) ([]CloudAccount, error) {
	return readRegistry[CloudAccount](cloudAccountsPath(statePath))
}

func WriteCloudAccounts(statePath string, list []CloudAccount) error {
	return writeRegistry(cloudAccountsPath(statePath), list)
}

func consoleRegistryPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "console-certificates.json")
}

func cloudAccountsPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "cloud-accounts.json")
}
