package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ──────────────────────────────────────────────
// SetupLogging — basic
// ──────────────────────────────────────────────

func TestSetupLoggingBasic(t *testing.T) {
	dir := t.TempDir()
	logcfg := LogConfig{
		LogLevel:  "Info",
		LogFolder: dir + "/",
	}
	logger := SetupLogging(logcfg)
	if logger == nil {
		t.Fatal("SetupLogging returned nil logger")
	}

	// Verify a log file was created in the directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a .log file in the log directory")
	}
}

// ──────────────────────────────────────────────
// SetupLogging — log levels
// ──────────────────────────────────────────────

func TestSetupLoggingLevels(t *testing.T) {
	levels := []string{"Debug", "Info", "Warning", "Error"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			logcfg := LogConfig{
				LogLevel:  level,
				LogFolder: dir + "/",
			}
			logger := SetupLogging(logcfg)
			if logger == nil {
				t.Fatalf("SetupLogging returned nil for level %q", level)
			}
		})
	}
}

// ──────────────────────────────────────────────
// SetupLogging — empty LogFolder fallback
// ──────────────────────────────────────────────

func TestSetupLoggingEmptyLogFolder(t *testing.T) {
	// When LogFolder is empty, SetupLogging falls back to cwd + "/logs/"
	cwd, _ := os.Getwd()
	fallbackDir := cwd + "/logs/"
	os.MkdirAll(fallbackDir, 0750)
	defer os.RemoveAll(fallbackDir)

	logcfg := LogConfig{
		LogLevel:  "Info",
		LogFolder: "",
	}
	logger := SetupLogging(logcfg)
	if logger == nil {
		t.Fatal("SetupLogging returned nil logger")
	}

	// Verify log file was created in the fallback directory
	entries, err := os.ReadDir(fallbackDir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			found = true
			// Clean up the log file we created
			os.Remove(filepath.Join(fallbackDir, e.Name()))
			break
		}
	}
	if !found {
		t.Error("expected a .log file in the fallback log directory")
	}
}

// ──────────────────────────────────────────────
// SetupLogging — existing file rename
// ──────────────────────────────────────────────

func TestSetupLoggingExistingFileRename(t *testing.T) {
	dir := t.TempDir()

	// Build the expected filename: ApplicationName + "_" + timestamp + ".log"
	// Since time is dynamic we create a file matching the expected pattern
	filename := ApplicationName + "_" + time.Now().Format("20060102_150405") + ".log"
	existingFile := filepath.Join(dir, filename)
	if err := os.WriteFile(existingFile, []byte("old log content"), 0644); err != nil {
		t.Fatal(err)
	}

	logcfg := LogConfig{
		LogLevel:  "Info",
		LogFolder: dir + "/",
	}
	logger := SetupLogging(logcfg)
	if logger == nil {
		t.Fatal("SetupLogging returned nil logger")
	}

	// The original file should have been renamed
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Errorf("expected at least 2 files (renamed + new), got %d", len(entries))
	}
}

// ──────────────────────────────────────────────
// SetupLogging — duplicate renamed file (counter suffix)
// ──────────────────────────────────────────────

func TestSetupLoggingDuplicateRename(t *testing.T) {
	dir := t.TempDir()

	// Build the expected filename
	filename := ApplicationName + "_" + time.Now().Format("20060102_150405") + ".log"
	existingFile := filepath.Join(dir, filename)
	if err := os.WriteFile(existingFile, []byte("old log"), 0644); err != nil {
		t.Fatal(err)
	}

	// Also pre-create the renamed file (filename + "_" + today)
	today := time.Now().Format("2006-01-02")
	renamedFile := filepath.Join(dir, filename+"_"+today)
	if err := os.WriteFile(renamedFile, []byte("already renamed"), 0644); err != nil {
		t.Fatal(err)
	}

	logcfg := LogConfig{
		LogLevel:  "Info",
		LogFolder: dir + "/",
	}
	logger := SetupLogging(logcfg)
	if logger == nil {
		t.Fatal("SetupLogging returned nil logger")
	}

	// Verify we now have at least 3 files: the counter-suffixed rename, the original rename, and the new log
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 3 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("expected at least 3 files, got %d: %v", len(entries), names)
	}

	// Verify a counter-suffixed file exists
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filename+"_"+today+".") {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("expected a counter-suffixed file, got files: %v", names)
	}
}
