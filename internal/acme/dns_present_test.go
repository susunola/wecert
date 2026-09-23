package acme

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// callWithTimeout must not wait forever when the provider hangs. lego's
// challenge.Provider takes no context, so the only defence is a wall-clock bound on
// the wait (the underlying call may still finish later).
func TestCallWithTimeoutBoundsAHungProvider(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	err := callWithTimeout("present TXT", 50*time.Millisecond, func() error {
		<-release
		return errors.New("should not be returned")
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a hung provider call must time out")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("the error must say it timed out, got %q", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("waited %s, want about 50ms", elapsed)
	}
}

func TestCallWithTimeoutReturnsTheInnerError(t *testing.T) {
	want := errors.New("inner failure")
	if err := callWithTimeout("cleanup TXT", time.Second, func() error { return want }); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}
