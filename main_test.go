package main

import (
	"strings"
	"testing"
)

// ──────────────────────────────────────────────
// sort_by_rcount
// ──────────────────────────────────────────────

func TestSortByRcountEmpty(t *testing.T) {
	got := sort_by_rcount(map[string]int{})
	if got != "" {
		t.Errorf("expected empty string for empty map, got %q", got)
	}
}

func TestSortByRcountSingle(t *testing.T) {
	got := sort_by_rcount(map[string]int{"1.2.3.4": 42})
	if !strings.Contains(got, "1.2.3.4") {
		t.Errorf("output should contain IP, got %q", got)
	}
	if !strings.Contains(got, "42") {
		t.Errorf("output should contain count, got %q", got)
	}
}

func TestSortByRcountDescendingOrder(t *testing.T) {
	m := map[string]int{
		"10.0.0.1": 100,
		"10.0.0.2": 50,
		"10.0.0.3": 200,
	}
	got := sort_by_rcount(m)

	// The highest count (200) should appear before the lowest (50)
	pos200 := strings.Index(got, "200")
	pos100 := strings.Index(got, "100")
	pos50 := strings.Index(got, "50")

	if pos200 == -1 || pos100 == -1 || pos50 == -1 {
		t.Fatalf("missing counts in output: %q", got)
	}
	if pos200 > pos100 || pos100 > pos50 {
		t.Errorf("expected descending order (200, 100, 50), got: %s", got)
	}
}

func TestSortByRcountTies(t *testing.T) {
	m := map[string]int{
		"10.0.0.1": 5,
		"10.0.0.2": 5,
	}
	got := sort_by_rcount(m)

	if !strings.Contains(got, "10.0.0.1") {
		t.Errorf("output should contain 10.0.0.1, got %q", got)
	}
	if !strings.Contains(got, "10.0.0.2") {
		t.Errorf("output should contain 10.0.0.2, got %q", got)
	}
}
