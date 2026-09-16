package main

import (
	"fmt"
	"testing"

	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func cert(id string) *ssl.Certificates {
	return &ssl.Certificates{CertificateId: &id}
}

func ids(certs []*ssl.Certificates) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, *c.CertificateId)
	}
	return out
}

// The regression this pins: the API leaves TotalCount null in some responses, and reading
// a nil total as 0 stopped the walk after the first page. The walk decides what gets
// deleted, so the command then reported a complete cleanup over a truncated list.
func TestListAllPagesWalksPastTheFirstPageWithoutTotalCount(t *testing.T) {
	var offsets []uint64
	got, err := listAllPages(2, 10, func(offset, limit uint64) (certPage, error) {
		offsets = append(offsets, offset)
		switch offset {
		case 0:
			return certPage{certs: []*ssl.Certificates{cert("a"), cert("b")}}, nil
		case 2:
			// No TotalCount, exactly like the responses that caused the bug.
			return certPage{certs: []*ssl.Certificates{cert("c"), cert("d")}}, nil
		default:
			return certPage{certs: []*ssl.Certificates{cert("e")}}, nil
		}
	})
	if err != nil {
		t.Fatalf("listAllPages: %v", err)
	}
	if want := []string{"a", "b", "c", "d", "e"}; fmt.Sprint(ids(got)) != fmt.Sprint(want) {
		t.Errorf("walked %v, want %v", ids(got), want)
	}
	if fmt.Sprint(offsets) != "[0 2 4]" {
		t.Errorf("offsets = %v, want [0 2 4]", offsets)
	}
}

// A page smaller than the limit means the list is exhausted, even when the server reported
// a larger total (or none at all).
func TestListAllPagesStopsOnAShortPage(t *testing.T) {
	calls := 0
	total := uint64(10)
	got, err := listAllPages(3, 10, func(offset, _ uint64) (certPage, error) {
		calls++
		if offset == 0 {
			return certPage{certs: []*ssl.Certificates{cert("a"), cert("b"), cert("c")}, total: &total}, nil
		}
		return certPage{certs: []*ssl.Certificates{cert("d")}, total: &total}, nil
	})
	if err != nil {
		t.Fatalf("listAllPages: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d calls, want 2", calls)
	}
	if len(got) != 4 {
		t.Errorf("collected %d certificates, want 4", len(got))
	}
}

// A present TotalCount still ends the walk at the end of the list, without a wasted request.
func TestListAllPagesHonoursTotalCount(t *testing.T) {
	calls := 0
	total := uint64(2)
	got, err := listAllPages(2, 10, func(offset, _ uint64) (certPage, error) {
		calls++
		return certPage{certs: []*ssl.Certificates{cert("a"), cert("b")}, total: &total}, nil
	})
	if err != nil {
		t.Fatalf("listAllPages: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d calls, want 1: TotalCount was reached", calls)
	}
	if len(got) != 2 {
		t.Errorf("collected %d certificates, want 2", len(got))
	}
}

// A server that ignores Offset never returns a short page, so the walk needs its own stop
// rather than looping forever inside a command that then deletes things.
func TestListAllPagesRefusesToLoopForever(t *testing.T) {
	got, err := listAllPages(1, 3, func(uint64, uint64) (certPage, error) {
		return certPage{certs: []*ssl.Certificates{cert("same")}}, nil
	})
	if err == nil {
		t.Fatalf("a non-advancing listing must be an error, got %d certificates", len(got))
	}
}

func TestListAllPagesPropagatesFetchErrors(t *testing.T) {
	boom := fmt.Errorf("ssl api is down")
	if _, err := listAllPages(2, 10, func(uint64, uint64) (certPage, error) {
		return certPage{}, boom
	}); err == nil {
		t.Fatal("a fetch failure must be returned")
	}
}
