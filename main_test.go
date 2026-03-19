package main

import (
	"strings"
	"testing"
)

// ──────────────────────────────────────────────
// sortByRcount
// ──────────────────────────────────────────────

func TestSortByRcountEmpty(t *testing.T) {
	got := sortByRcount(map[string]int{})
	if got != "" {
		t.Errorf("expected empty string for empty map, got %q", got)
	}
}

func TestSortByRcountSingle(t *testing.T) {
	got := sortByRcount(map[string]int{"1.2.3.4": 42})
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
	got := sortByRcount(m)

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
	got := sortByRcount(m)

	if !strings.Contains(got, "10.0.0.1") {
		t.Errorf("output should contain 10.0.0.1, got %q", got)
	}
	if !strings.Contains(got, "10.0.0.2") {
		t.Errorf("output should contain 10.0.0.2, got %q", got)
	}
}

// ──────────────────────────────────────────────
// sortByRtime
// ──────────────────────────────────────────────

func TestSortByRtimeEmpty(t *testing.T) {
	got := sortByRtime(map[string]float64{})
	if got != "" {
		t.Errorf("expected empty string for empty map, got %q", got)
	}
}

func TestSortByRtimeSingle(t *testing.T) {
	got := sortByRtime(map[string]float64{"1.2.3.4": 1.5})
	if !strings.Contains(got, "1.2.3.4") {
		t.Errorf("output should contain IP, got %q", got)
	}
	if !strings.Contains(got, "1.5") {
		t.Errorf("output should contain rtime, got %q", got)
	}
}

func TestSortByRtimeDescendingOrder(t *testing.T) {
	m := map[string]float64{
		"10.0.0.1": 1.2,
		"10.0.0.2": 5.7,
		"10.0.0.3": 0.3,
	}
	got := sortByRtime(m)

	pos57 := strings.Index(got, "5.7")
	pos12 := strings.Index(got, "1.2")
	pos03 := strings.Index(got, "0.3")

	if pos57 == -1 || pos12 == -1 || pos03 == -1 {
		t.Fatalf("missing rtimes in output: %q", got)
	}
	if pos57 > pos12 || pos12 > pos03 {
		t.Errorf("expected descending order (5.7, 1.2, 0.3), got: %s", got)
	}
}

func TestSortByRtimeFormatOneDecimal(t *testing.T) {
	got := sortByRtime(map[string]float64{"1.2.3.4": 3.0})
	// formatted as %.1f so should show "3.0", not "3"
	if !strings.Contains(got, "3.0") {
		t.Errorf("expected %%.1f formatting (e.g. 3.0), got %q", got)
	}
}
