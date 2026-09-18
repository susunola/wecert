package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
