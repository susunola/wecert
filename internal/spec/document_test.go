package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// An oversized document must be refused, not silently truncated.
//
// io.LimitReader cut the read at 16 MiB and the parser was handed the prefix: a cut that lands on a
// certificate boundary is a complete YAML document, so the daemon acted on a partial fleet --
// measured with 114,909 of 200,000 certificates accepted as the desired state. The reader now takes
// one byte past the cap and refuses the read.
func TestAnOversizedDocumentIsRefusedRatherThanTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desired-state.yaml")

	// A document that is a valid complete state at any prefix boundary is the dangerous shape, so
	// build one out of many independent list entries and cut it past the cap.
	var b strings.Builder
	b.WriteString("generatedAt: " + time.Now().UTC().Format(time.RFC3339) + "\nrevision: r1\ncertificates:\n")
	for i := 0; b.Len() < maxDocumentBytes+(1<<20); i++ {
		fmt.Fprintf(&b, "  - name: cert-%06d\n    domains: [d%06d.example.com]\n", i, i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadDocument(path); err == nil {
		t.Fatal("a document past the size cap must be refused: acting on a truncated prefix drops " +
			"every certificate that was cut off")
	} else if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("the refusal must name the size, got %v", err)
	}
}

// A desired-state document that merely ends with a separator is one document, not two.
//
// The multi-document guard used to live twice: config's copy skipped a trailing empty
// "---", and this package's copy refused anything Decode returned without error -- so
// the same trailing separator that Load accepts made LoadDocument fail, which in enforce
// mode freezes the document at its old revision. Both now share config.RejectExtraDocuments.
func TestLoadDocumentAcceptsATrailingDocumentSeparator(t *testing.T) {
	// WriteDocument produces a revision that matches its certificates; the trailing
	// separator is the only thing under test, so the envelope has to be valid first.
	base := writeDoc(t, &Document{
		APIVersion:  APIVersionV1,
		Kind:        KindDesiredState,
		GeneratedAt: time.Now().UTC(),
		Certificates: []config.Certificate{
			{Name: "example-com", Domains: []string{"example.com"}},
		},
	})
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		"---\n",
		"---",
		"---\n---\n",
		"---\n# nothing but a comment\n",
	} {
		path := filepath.Join(t.TempDir(), "desired-state.yaml")
		if err := os.WriteFile(path, append(append([]byte{}, raw...), body...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err != nil {
			t.Errorf("a document ending in %q is one document and must load, got %v", body, err)
		}
	}
}

// A second document with content in it is still refused -- the trailing-separator
// exception must not widen into "any extra document is fine".
func TestLoadDocumentStillRejectsASecondYAMLDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired-state.yaml")
	src := "apiVersion: wecert/v1\n" +
		"kind: DesiredState\n" +
		"generatedAt: " + time.Now().UTC().Format(time.RFC3339) + "\n" +
		"revision: r1\n" +
		"certificates:\n" +
		"  - name: example-com\n" +
		"    domains: [example.com]\n" +
		"---\n" +
		"certificates:\n" +
		"  - name: other-com\n" +
		"    domains: [other.com]\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(path); err == nil {
		t.Fatal("a document with two YAML documents must be rejected, not half-ignored")
	} else if !strings.Contains(err.Error(), "more than one YAML document") {
		t.Errorf("the error should explain the cause, got %v", err)
	}
}
