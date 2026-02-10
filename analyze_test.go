package main

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

// setupTestGlobals initializes the global variables needed by the functions under test.
func setupTestGlobals() {
	// discard logger so tests don't produce log output
	LogIt = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

	// default config
	config = ApplicationConfig{
		DateLayout:   "02/Jan/2006:15:04:05 -0700",
		OutputFolder: os.TempDir() + "/",
		LogType:      "apache",
		LogFormat:    `%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"`,
	}

	// default log_2_analyze
	log_2_analyze = &Log2Analyze{
		DateLayout: "02/Jan/2006:15:04:05 -0700",
	}

	// default flag values (these are already initialised by flag.Int/String, but
	// we set them explicitly here so tests don't depend on flag.Parse order)
	defaultIPClass := "D"
	IPclass = &defaultIPClass

	defaultIP := ""
	ip_adress = &defaultIP

	defaultNotIP := ""
	not_ip = &defaultNotIP

	defaultResponseCode := 0
	response_code = &defaultResponseCode

	defaultNoResponseCode := 0
	no_response_code = &defaultNoResponseCode

	defaultTopIPs := 5
	topIPsCount = &defaultTopIPs

	defaultTimeRange := 5
	timeRange = &defaultTimeRange

	defaultCombined := false
	combined_file = &defaultCombined
}

// ──────────────────────────────────────────────
// LogEntry.Between
// ──────────────────────────────────────────────

func TestBetween(t *testing.T) {
	start := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 10, 13, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		ts     time.Time
		expect bool
	}{
		{"inside range", time.Date(2026, 2, 10, 12, 30, 0, 0, time.UTC), true},
		{"exactly at start", start, false},
		{"exactly at end", end, false},
		{"before range", time.Date(2026, 2, 10, 11, 0, 0, 0, time.UTC), false},
		{"after range", time.Date(2026, 2, 10, 14, 0, 0, 0, time.UTC), false},
		{"one second after start", start.Add(1 * time.Second), true},
		{"one second before end", end.Add(-1 * time.Second), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := LogEntry{TimeStamp: tt.ts}
			got := e.Between(start, end)
			if got != tt.expect {
				t.Errorf("Between(%v, %v) for ts=%v: got %v, want %v", start, end, tt.ts, got, tt.expect)
			}
		})
	}
}

// ──────────────────────────────────────────────
// parse_apache
// ──────────────────────────────────────────────

func TestParseApache(t *testing.T) {
	setupTestGlobals()

	line := `192.168.1.100 - frank [10/Feb/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"`

	ip, class, ts, method, request, code, _ := parse_apache(line)

	if ip != "192.168.1.100" {
		t.Errorf("ip: got %q, want %q", ip, "192.168.1.100")
	}
	// IPclass=D means class == full IP
	if class != "192.168.1.100" {
		t.Errorf("class: got %q, want %q", class, "192.168.1.100")
	}
	expectedTime := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	if !ts.Equal(expectedTime) {
		t.Errorf("timestamp: got %v, want %v", ts, expectedTime)
	}
	if method != "GET" {
		t.Errorf("method: got %q, want %q", method, "GET")
	}
	if request != "/index.html" {
		t.Errorf("request: got %q, want %q", request, "/index.html")
	}
	if code != 200 {
		t.Errorf("code: got %d, want %d", code, 200)
	}
}

func TestParseApacheIPClassA(t *testing.T) {
	setupTestGlobals()
	classA := "A"
	IPclass = &classA

	line := `10.20.30.40 - - [10/Feb/2026:12:00:00 +0000] "POST /api HTTP/1.1" 201 512 "-" "curl/7.0"`
	ip, class, _, method, request, code, _ := parse_apache(line)

	if ip != "10.20.30.40" {
		t.Errorf("ip: got %q, want %q", ip, "10.20.30.40")
	}
	if class != "10" {
		t.Errorf("class A: got %q, want %q", class, "10")
	}
	if method != "POST" {
		t.Errorf("method: got %q, want %q", method, "POST")
	}
	if request != "/api" {
		t.Errorf("request: got %q, want %q", request, "/api")
	}
	if code != 201 {
		t.Errorf("code: got %d, want %d", code, 201)
	}
}

func TestParseApacheIPClassB(t *testing.T) {
	setupTestGlobals()
	classB := "B"
	IPclass = &classB

	line := `10.20.30.40 - - [10/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"`
	_, class, _, _, _, _, _ := parse_apache(line)

	if class != "10.20" {
		t.Errorf("class B: got %q, want %q", class, "10.20")
	}
}

func TestParseApacheIPClassC(t *testing.T) {
	setupTestGlobals()
	classC := "C"
	IPclass = &classC

	line := `10.20.30.40 - - [10/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"`
	_, class, _, _, _, _, _ := parse_apache(line)

	if class != "10.20.30" {
		t.Errorf("class C: got %q, want %q", class, "10.20.30")
	}
}

func TestParseApacheShortLine(t *testing.T) {
	setupTestGlobals()

	// a line missing the user-agent and referer — the padding logic should prevent a crash
	line := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512`
	ip, _, _, method, _, code, _ := parse_apache(line)

	if ip != "192.168.1.1" {
		t.Errorf("ip: got %q, want %q", ip, "192.168.1.1")
	}
	if method != "GET" {
		t.Errorf("method: got %q, want %q", method, "GET")
	}
	if code != 200 {
		t.Errorf("code: got %d, want %d", code, 200)
	}
}

// ──────────────────────────────────────────────
// parse_apache_atmire
// ──────────────────────────────────────────────

func TestParseApacheAtmire(t *testing.T) {
	setupTestGlobals()

	line := `172.16.0.1 - admin [10/Feb/2026:08:30:00 +0000] "GET /xmlui/handle/123 HTTP/1.1" 200 5678 "http://ref.example.com" "Mozilla/5.0"`

	ip, class, ts, method, request, code, _ := parse_apache_atmire(line)

	if ip != "172.16.0.1" {
		t.Errorf("ip: got %q, want %q", ip, "172.16.0.1")
	}
	if class != "172.16.0.1" {
		t.Errorf("class: got %q, want %q", class, "172.16.0.1")
	}
	expectedTime := time.Date(2026, 2, 10, 8, 30, 0, 0, time.UTC)
	if !ts.Equal(expectedTime) {
		t.Errorf("timestamp: got %v, want %v", ts, expectedTime)
	}
	if method != "GET" {
		t.Errorf("method: got %q, want %q", method, "GET")
	}
	if request != "/xmlui/handle/123" {
		t.Errorf("request: got %q, want %q", request, "/xmlui/handle/123")
	}
	if code != 200 {
		t.Errorf("code: got %d, want %d", code, 200)
	}
}

// ──────────────────────────────────────────────
// parse_rosetta
// ──────────────────────────────────────────────

func TestParseRosetta(t *testing.T) {
	setupTestGlobals()

	// rosetta format: extra field before IP at position 0, real IP at 1 if pos-1 is "-"
	line := `server1 10.0.0.5 - admin [10/Feb/2026:09:00:00 +0000] "DELETE /resource/42 HTTP/1.1" 204 0 "-" "HTTPie/3.0"`

	ip, _, ts, method, request, code, _ := parse_rosetta(line)

	if ip != "10.0.0.5" {
		t.Errorf("ip: got %q, want %q", ip, "10.0.0.5")
	}
	expectedTime := time.Date(2026, 2, 10, 9, 0, 0, 0, time.UTC)
	if !ts.Equal(expectedTime) {
		t.Errorf("timestamp: got %v, want %v", ts, expectedTime)
	}
	if method != "DELETE" {
		t.Errorf("method: got %q, want %q", method, "DELETE")
	}
	if request != "/resource/42" {
		t.Errorf("request: got %q, want %q", request, "/resource/42")
	}
	if code != 204 {
		t.Errorf("code: got %d, want %d", code, 204)
	}
}

func TestParseRosettaDashFallback(t *testing.T) {
	setupTestGlobals()

	// when parts[1] is "-", IP comes from parts[0]
	line := `10.0.0.5 - - admin [10/Feb/2026:09:00:00 +0000] "GET /page HTTP/1.1" 200 100 "-" "-"`

	ip, _, _, _, _, _, _ := parse_rosetta(line)

	if ip != "10.0.0.5" {
		t.Errorf("ip: got %q, want %q", ip, "10.0.0.5")
	}
}

// ──────────────────────────────────────────────
// create_entry (dispatch to the right parser)
// ──────────────────────────────────────────────

func TestCreateEntryApache(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"

	line := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET /test HTTP/1.1" 404 0 "-" "-"`
	entry := create_entry(line)

	if entry.IP != "192.168.1.1" {
		t.Errorf("IP: got %q, want %q", entry.IP, "192.168.1.1")
	}
	if entry.Code != 404 {
		t.Errorf("Code: got %d, want %d", entry.Code, 404)
	}
	if entry.Method != "GET" {
		t.Errorf("Method: got %q, want %q", entry.Method, "GET")
	}
	if entry.Request != "/test" {
		t.Errorf("Request: got %q, want %q", entry.Request, "/test")
	}
}

func TestCreateEntryApacheAtmire(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache_atmire"

	line := `10.0.0.1 - - [10/Feb/2026:12:00:00 +0000] "POST /upload HTTP/1.1" 201 999 "-" "-"`
	entry := create_entry(line)

	if entry.IP != "10.0.0.1" {
		t.Errorf("IP: got %q, want %q", entry.IP, "10.0.0.1")
	}
	if entry.Code != 201 {
		t.Errorf("Code: got %d, want %d", entry.Code, 201)
	}
}

// ──────────────────────────────────────────────
// create_time_range
// ──────────────────────────────────────────────

func TestCreateTimeRange(t *testing.T) {
	setupTestGlobals()

	start, end := create_time_range("14:00", 5, "2026-02-10")

	// end should be 14:00 on 2026-02-10 in local tz
	if end.Hour() != 14 || end.Minute() != 0 {
		t.Errorf("end time: got %v, want 14:00", end.Format("15:04"))
	}
	if end.Year() != 2026 || end.Month() != 2 || end.Day() != 10 {
		t.Errorf("end date: got %v, want 2026-02-10", end.Format("2006-01-02"))
	}

	// start should be 5 minutes before end
	diff := end.Sub(start)
	if diff != 5*time.Minute {
		t.Errorf("time range: got %v, want %v", diff, 5*time.Minute)
	}
}

func TestCreateTimeRangeZero(t *testing.T) {
	setupTestGlobals()

	start, end := create_time_range("10:00", 0, "2026-02-10")

	// with timerange 0, start should be zero value
	if !start.IsZero() {
		t.Errorf("start should be zero value, got %v", start)
	}
	// end should still be set
	if end.Hour() != 10 || end.Minute() != 0 {
		t.Errorf("end time: got %v, want 10:00", end.Format("15:04"))
	}
}

func TestCreateTimeRangeLarger(t *testing.T) {
	setupTestGlobals()

	start, end := create_time_range("12:00", 60, "2026-02-10")

	diff := end.Sub(start)
	if diff != 60*time.Minute {
		t.Errorf("time range: got %v, want %v", diff, 60*time.Minute)
	}
}

// ──────────────────────────────────────────────
// fill_placeholder_lut
// ──────────────────────────────────────────────

func TestFillPlaceholderLut(t *testing.T) {
	setupTestGlobals()
	placeholder_lut = make(map[string]int)

	fill_placeholder_lut()

	// With the default log format, %t is unquoted so it expands to ts1/ts2.
	// "%r" is quoted so strings.Fields keeps it as one token (no m/r/p expansion).
	expectedKeys := []string{"%h", "ts1", "ts2", "%>s"}
	for _, key := range expectedKeys {
		if _, ok := placeholder_lut[key]; !ok {
			t.Errorf("expected key %q in placeholder_lut, but not found. lut = %v", key, placeholder_lut)
		}
	}

	if placeholder_lut["%h"] != 0 {
		t.Errorf("%%h position: got %d, want 0", placeholder_lut["%h"])
	}
}

func TestFillPlaceholderLutUnquoted(t *testing.T) {
	setupTestGlobals()
	placeholder_lut = make(map[string]int)
	// when %r is unquoted, it should expand to m, r, p
	config.LogFormat = `%h %l %u %t %r %>s %O`

	fill_placeholder_lut()

	expectedKeys := []string{"%h", "ts1", "ts2", "m", "r", "p", "%>s"}
	for _, key := range expectedKeys {
		if _, ok := placeholder_lut[key]; !ok {
			t.Errorf("expected key %q in placeholder_lut, but not found. lut = %v", key, placeholder_lut)
		}
	}
}

// ──────────────────────────────────────────────
// GetTopIPs
// ──────────────────────────────────────────────

func TestGetTopIPs(t *testing.T) {
	setupTestGlobals()

	l := Log2Analyze{
		Entries: []LogEntry{
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 200},
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 200},
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 404},
			{IP: "2.2.2.2", Class: "2.2.2.2", Code: 200},
			{IP: "2.2.2.2", Class: "2.2.2.2", Code: 500},
			{IP: "3.3.3.3", Class: "3.3.3.3", Code: 200},
		},
	}

	topIPs, codeCounts := l.GetTopIPs()

	// should return all 3 IPs (less than topIPsCount=5)
	if len(topIPs) != 3 {
		t.Errorf("expected 3 top IPs, got %d", len(topIPs))
	}
	if topIPs["1.1.1.1"] != 3 {
		t.Errorf("1.1.1.1 count: got %d, want 3", topIPs["1.1.1.1"])
	}
	if topIPs["2.2.2.2"] != 2 {
		t.Errorf("2.2.2.2 count: got %d, want 2", topIPs["2.2.2.2"])
	}
	if topIPs["3.3.3.3"] != 1 {
		t.Errorf("3.3.3.3 count: got %d, want 1", topIPs["3.3.3.3"])
	}

	// code counts
	if codeCounts[200] != 4 {
		t.Errorf("code 200 count: got %d, want 4", codeCounts[200])
	}
	if codeCounts[404] != 1 {
		t.Errorf("code 404 count: got %d, want 1", codeCounts[404])
	}
	if codeCounts[500] != 1 {
		t.Errorf("code 500 count: got %d, want 1", codeCounts[500])
	}
}

func TestGetTopIPsLimitsToN(t *testing.T) {
	setupTestGlobals()
	n := 2
	topIPsCount = &n

	l := Log2Analyze{
		Entries: []LogEntry{
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 200},
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 200},
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 200},
			{IP: "2.2.2.2", Class: "2.2.2.2", Code: 200},
			{IP: "2.2.2.2", Class: "2.2.2.2", Code: 200},
			{IP: "3.3.3.3", Class: "3.3.3.3", Code: 200},
			{IP: "4.4.4.4", Class: "4.4.4.4", Code: 200},
		},
	}

	topIPs, _ := l.GetTopIPs()

	if len(topIPs) != 2 {
		t.Errorf("expected 2 top IPs, got %d: %v", len(topIPs), topIPs)
	}
	// should contain the two highest: 1.1.1.1 (3) and 2.2.2.2 (2)
	if _, ok := topIPs["1.1.1.1"]; !ok {
		t.Error("expected 1.1.1.1 in top IPs")
	}
	if _, ok := topIPs["2.2.2.2"]; !ok {
		t.Error("expected 2.2.2.2 in top IPs")
	}
}

func TestGetTopIPsEmpty(t *testing.T) {
	setupTestGlobals()

	l := Log2Analyze{Entries: []LogEntry{}}
	topIPs, codeCounts := l.GetTopIPs()

	if len(topIPs) != 0 {
		t.Errorf("expected empty top IPs, got %d", len(topIPs))
	}
	if len(codeCounts) != 0 {
		t.Errorf("expected empty code counts, got %d", len(codeCounts))
	}
}

func TestGetTopIPsZeroN(t *testing.T) {
	setupTestGlobals()
	n := 0
	topIPsCount = &n

	l := Log2Analyze{
		Entries: []LogEntry{
			{IP: "1.1.1.1", Class: "1.1.1.1", Code: 200},
			{IP: "2.2.2.2", Class: "2.2.2.2", Code: 200},
		},
	}

	topIPs, _ := l.GetTopIPs()

	// when topIPsCount=0, entries > 0 && *topIPsCount <= 0, so entries stays at len(ip_count)
	if len(topIPs) != 2 {
		t.Errorf("expected 2 IPs (all), got %d", len(topIPs))
	}
}

func TestGetTopIPsUsesClass(t *testing.T) {
	setupTestGlobals()

	// entries with different IPs but same class should be grouped
	l := Log2Analyze{
		Entries: []LogEntry{
			{IP: "10.0.0.1", Class: "10.0.0", Code: 200},
			{IP: "10.0.0.2", Class: "10.0.0", Code: 200},
			{IP: "10.0.0.3", Class: "10.0.0", Code: 200},
			{IP: "20.0.0.1", Class: "20.0.0", Code: 200},
		},
	}

	topIPs, _ := l.GetTopIPs()

	if topIPs["10.0.0"] != 3 {
		t.Errorf("class 10.0.0 count: got %d, want 3", topIPs["10.0.0"])
	}
	if topIPs["20.0.0"] != 1 {
		t.Errorf("class 20.0.0 count: got %d, want 1", topIPs["20.0.0"])
	}
}

// ──────────────────────────────────────────────
// RetrieveEntries (integration-style with temp file)
// ──────────────────────────────────────────────

func writeTempLogFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "topfive-test-*.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestRetrieveEntriesWholeFile(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"

	logContent := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET /page1 HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:01:00 +0000] "GET /page2 HTTP/1.1" 200 200 "-" "-"
10.0.0.1 - - [10/Feb/2026:12:02:00 +0000] "POST /api HTTP/1.1" 201 300 "-" "-"
`
	tmpFile := writeTempLogFile(t, logContent)
	defer os.Remove(tmpFile)

	l := &Log2Analyze{
		FileName:   tmpFile,
		DateLayout: "02/Jan/2006:15:04:05 -0700",
	}
	log_2_analyze = l

	// timerange=0 means whole file
	l.RetrieveEntries("12:05", 0)

	if l.EntryCount != 3 {
		t.Errorf("EntryCount: got %d, want 3", l.EntryCount)
	}
}

func TestRetrieveEntriesWithTimeRange(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"

	// create_time_range uses the local timezone, so the log entries must use it too
	tz := time.Now().Format("-0700")

	logContent := fmt.Sprintf(
		`192.168.1.1 - - [10/Feb/2026:11:50:00 %s] "GET /old HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:11:56:00 %s] "GET /recent1 HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:11:58:00 %s] "GET /recent2 HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:01:00 %s] "GET /future HTTP/1.1" 200 100 "-" "-"
`, tz, tz, tz, tz)

	tmpFile := writeTempLogFile(t, logContent)
	defer os.Remove(tmpFile)

	l := &Log2Analyze{
		FileName:     tmpFile,
		DateLayout:   "02/Jan/2006:15:04:05 -0700",
		Date2analyze: "2026-02-10",
	}
	log_2_analyze = l

	// 5 minute range ending at 12:00, so 11:55 - 12:00
	l.RetrieveEntries("12:00", 5)

	// should include 11:56 and 11:58 but not 11:50 (before range) or 12:01 (after range)
	if l.EntryCount != 2 {
		t.Errorf("EntryCount: got %d, want 2", l.EntryCount)
		for _, e := range l.Entries {
			t.Logf("  entry: %s %s", e.TimeStamp.Format("15:04:05 -0700"), e.Request)
		}
	}
}

func TestRetrieveEntriesIPFilter(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"
	filterIP := "192.168.1.1"
	ip_adress = &filterIP

	logContent := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "-"
10.0.0.1 - - [10/Feb/2026:12:01:00 +0000] "GET /b HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:02:00 +0000] "GET /c HTTP/1.1" 200 100 "-" "-"
`
	tmpFile := writeTempLogFile(t, logContent)
	defer os.Remove(tmpFile)

	l := &Log2Analyze{
		FileName:   tmpFile,
		DateLayout: "02/Jan/2006:15:04:05 -0700",
	}
	log_2_analyze = l

	l.RetrieveEntries("12:05", 0)

	if l.EntryCount != 2 {
		t.Errorf("EntryCount with IP filter: got %d, want 2", l.EntryCount)
	}
	for _, e := range l.Entries {
		if e.IP != "192.168.1.1" {
			t.Errorf("unexpected IP in results: %s", e.IP)
		}
	}
}

func TestRetrieveEntriesNotIPFilter(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"
	excludeIP := "10.0.0.1"
	not_ip = &excludeIP

	logContent := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "-"
10.0.0.1 - - [10/Feb/2026:12:01:00 +0000] "GET /b HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:02:00 +0000] "GET /c HTTP/1.1" 200 100 "-" "-"
`
	tmpFile := writeTempLogFile(t, logContent)
	defer os.Remove(tmpFile)

	l := &Log2Analyze{
		FileName:   tmpFile,
		DateLayout: "02/Jan/2006:15:04:05 -0700",
	}
	log_2_analyze = l

	l.RetrieveEntries("12:05", 0)

	if l.EntryCount != 2 {
		t.Errorf("EntryCount with not-IP filter: got %d, want 2", l.EntryCount)
	}
	for _, e := range l.Entries {
		if e.IP == "10.0.0.1" {
			t.Error("10.0.0.1 should have been excluded")
		}
	}
}

func TestRetrieveEntriesResponseCodeFilter(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"
	rc := 404
	response_code = &rc

	logContent := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:01:00 +0000] "GET /b HTTP/1.1" 404 0 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:02:00 +0000] "GET /c HTTP/1.1" 404 0 "-" "-"
`
	tmpFile := writeTempLogFile(t, logContent)
	defer os.Remove(tmpFile)

	l := &Log2Analyze{
		FileName:   tmpFile,
		DateLayout: "02/Jan/2006:15:04:05 -0700",
	}
	log_2_analyze = l

	l.RetrieveEntries("12:05", 0)

	if l.EntryCount != 2 {
		t.Errorf("EntryCount with response code filter: got %d, want 2", l.EntryCount)
	}
}

func TestRetrieveEntriesQueryStringFilter(t *testing.T) {
	setupTestGlobals()
	config.LogType = "apache"

	logContent := `192.168.1.1 - - [10/Feb/2026:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:01:00 +0000] "GET /page HTTP/1.1" 200 100 "-" "-"
192.168.1.1 - - [10/Feb/2026:12:02:00 +0000] "GET /api/items HTTP/1.1" 200 100 "-" "-"
`
	tmpFile := writeTempLogFile(t, logContent)
	defer os.Remove(tmpFile)

	l := &Log2Analyze{
		FileName:     tmpFile,
		DateLayout:   "02/Jan/2006:15:04:05 -0700",
		QueryString:  "/api",
	}
	log_2_analyze = l

	l.RetrieveEntries("12:05", 0)

	if l.EntryCount != 2 {
		t.Errorf("EntryCount with query string filter: got %d, want 2", l.EntryCount)
	}
}

// ──────────────────────────────────────────────
// WriteOutputFiles (smoke test - just verify no crash)
// ──────────────────────────────────────────────

func TestWriteOutputFilesCombined(t *testing.T) {
	setupTestGlobals()
	cb := true
	combined_file = &cb
	tr := 5
	timeRange = &tr
	config.OutputFolder = os.TempDir() + "/"

	l := Log2Analyze{
		FileName:   "test.log",
		DateLayout: "02/Jan/2006:15:04:05 -0700",
		StartTime:  time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC),
		EndTime:    time.Date(2026, 2, 10, 12, 5, 0, 0, time.UTC),
		EntryCount: 2,
		Entries: []LogEntry{
			{IP: "1.1.1.1", Class: "1.1.1.1", TimeStamp: time.Date(2026, 2, 10, 12, 1, 0, 0, time.UTC), Method: "GET", Request: "/a", Code: 200},
			{IP: "2.2.2.2", Class: "2.2.2.2", TimeStamp: time.Date(2026, 2, 10, 12, 2, 0, 0, time.UTC), Method: "POST", Request: "/b", Code: 201},
		},
	}

	topIPs := map[string]int{"1.1.1.1": 1, "2.2.2.2": 1}
	codeCounts := map[int]int{200: 1, 201: 1}

	// should not panic
	l.WriteOutputFiles(topIPs, codeCounts)
}

func TestWriteOutputFilesSeparate(t *testing.T) {
	setupTestGlobals()
	cb := false
	combined_file = &cb
	config.OutputFolder = os.TempDir() + "/"

	l := Log2Analyze{
		FileName:   "test.log",
		DateLayout: "02/Jan/2006:15:04:05 -0700",
		EntryCount: 1,
		Entries: []LogEntry{
			{IP: "1.1.1.1", Class: "1.1.1.1", TimeStamp: time.Date(2026, 2, 10, 12, 1, 0, 0, time.UTC), Method: "GET", Request: "/x", Code: 200},
		},
	}

	topIPs := map[string]int{"1.1.1.1": 1}
	codeCounts := map[int]int{200: 1}

	// should not panic
	l.WriteOutputFiles(topIPs, codeCounts)
}

// ──────────────────────────────────────────────
// parse_log (logfmt format)
// ──────────────────────────────────────────────

func TestParseLog(t *testing.T) {
	setupTestGlobals()
	// parse_log relies on the LUT which needs unquoted %r to expand into m/r/p
	config.LogFormat = `%h %l %u %t %r %>s %O`
	placeholder_lut = make(map[string]int)
	fill_placeholder_lut()

	// line without surrounding quotes for the request part (matches the unquoted format)
	line := `172.16.0.55 - user [10/Feb/2026:15:30:00 +0000] PUT /update HTTP/1.1 200 512`

	ip, class, ts, method, request, code, _ := parse_log(line)

	if ip != "172.16.0.55" {
		t.Errorf("ip: got %q, want %q", ip, "172.16.0.55")
	}
	if class != "172.16.0.55" {
		t.Errorf("class: got %q, want %q", class, "172.16.0.55")
	}
	expectedTime := time.Date(2026, 2, 10, 15, 30, 0, 0, time.UTC)
	if !ts.Equal(expectedTime) {
		t.Errorf("timestamp: got %v, want %v", ts, expectedTime)
	}
	if method != "PUT" {
		t.Errorf("method: got %q, want %q", method, "PUT")
	}
	if request != "/update" {
		t.Errorf("request: got %q, want %q", request, "/update")
	}
	if code != 200 {
		t.Errorf("code: got %d, want %d", code, 200)
	}
}
