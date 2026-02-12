package main

import (
	"crypto/md5"
	"os"
	"path/filepath"
	"testing"
)

// ──────────────────────────────────────────────
// StringInSlice
// ──────────────────────────────────────────────

func TestStringInSlice(t *testing.T) {
	tests := []struct {
		name   string
		needle string
		hay    []string
		want   bool
	}{
		{"found", "b", []string{"a", "b", "c"}, true},
		{"not found", "z", []string{"a", "b", "c"}, false},
		{"empty slice", "a", []string{}, false},
		{"empty string found", "", []string{"a", "", "c"}, true},
		{"empty string not found", "", []string{"a", "b"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringInSlice(tt.needle, tt.hay)
			if got != tt.want {
				t.Errorf("StringInSlice(%q, %v) = %v, want %v", tt.needle, tt.hay, got, tt.want)
			}
		})
	}
}

// ──────────────────────────────────────────────
// GetStringSliceElementIndex
// ──────────────────────────────────────────────

func TestGetStringSliceElementIndex(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		value string
		want  int
	}{
		{"first element", []string{"a", "b", "c"}, "a", 0},
		{"middle element", []string{"a", "b", "c"}, "b", 1},
		{"last element", []string{"a", "b", "c"}, "c", 2},
		{"absent", []string{"a", "b", "c"}, "z", -1},
		{"empty slice", []string{}, "a", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetStringSliceElementIndex(tt.slice, tt.value)
			if got != tt.want {
				t.Errorf("GetStringSliceElementIndex(%v, %q) = %d, want %d", tt.slice, tt.value, got, tt.want)
			}
		})
	}
}

// ──────────────────────────────────────────────
// GetCleanPath
// ──────────────────────────────────────────────

func TestGetCleanPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"with dotdot", "/foo/bar/../baz", "/foo/baz"},
		{"double slashes", "/foo//bar", "/foo/bar"},
		{"trailing slash", "/foo/bar/", "/foo/bar"},
		{"already clean", "/foo/bar", "/foo/bar"},
		{"relative path", "foo/bar", "foo/bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCleanPath(tt.path)
			if got != tt.want {
				t.Errorf("GetCleanPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// ──────────────────────────────────────────────
// checknaddtrailingslash
// ──────────────────────────────────────────────

func TestChecknaddtrailingslash(t *testing.T) {
	t.Run("adds slash when missing", func(t *testing.T) {
		p := "/foo/bar"
		checknaddtrailingslash(&p)
		if p != "/foo/bar/" {
			t.Errorf("got %q, want %q", p, "/foo/bar/")
		}
	})
	t.Run("no double slash when present", func(t *testing.T) {
		p := "/foo/bar/"
		checknaddtrailingslash(&p)
		if p != "/foo/bar/" {
			t.Errorf("got %q, want %q", p, "/foo/bar/")
		}
	})
}

// ──────────────────────────────────────────────
// SeparateFileFromPath
// ──────────────────────────────────────────────

func TestSeparateFileFromPath(t *testing.T) {
	tests := []struct {
		name     string
		fullpath string
		wantPath string
		wantFile string
	}{
		{"full path", "/var/log/app.log", "/var/log", "app.log"},
		{"just filename", "app.log", ".", "app.log"},
		{"root path", "/app.log", "/", "app.log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotFile := SeparateFileFromPath(tt.fullpath)
			if gotPath != tt.wantPath {
				t.Errorf("path: got %q, want %q", gotPath, tt.wantPath)
			}
			if gotFile != tt.wantFile {
				t.Errorf("file: got %q, want %q", gotFile, tt.wantFile)
			}
		})
	}
}

// ──────────────────────────────────────────────
// CheckIfDir
// ──────────────────────────────────────────────

func TestCheckIfDir(t *testing.T) {
	t.Run("existing directory", func(t *testing.T) {
		dir := t.TempDir()
		if !CheckIfDir(dir) {
			t.Errorf("CheckIfDir(%q) = false, want true", dir)
		}
	})
	t.Run("existing file", func(t *testing.T) {
		f, err := os.CreateTemp("", "checkifdir-test-*")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		defer os.Remove(f.Name())
		if CheckIfDir(f.Name()) {
			t.Errorf("CheckIfDir(%q) = true for a file, want false", f.Name())
		}
	})
	t.Run("non-existent path", func(t *testing.T) {
		if CheckIfDir("/nonexistent/path/xyz123") {
			t.Error("CheckIfDir returned true for non-existent path")
		}
	})
}

// ──────────────────────────────────────────────
// FileExists
// ──────────────────────────────────────────────

func TestFileExists(t *testing.T) {
	t.Run("existing file", func(t *testing.T) {
		f, err := os.CreateTemp("", "fileexists-test-*")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		defer os.Remove(f.Name())
		if !FileExists(f.Name()) {
			t.Errorf("FileExists(%q) = false, want true", f.Name())
		}
	})
	t.Run("non-existent file", func(t *testing.T) {
		if FileExists("/nonexistent/file/xyz123.txt") {
			t.Error("FileExists returned true for non-existent file")
		}
	})
	t.Run("directory returns false", func(t *testing.T) {
		dir := t.TempDir()
		if FileExists(dir) {
			t.Errorf("FileExists(%q) = true for a directory, want false", dir)
		}
	})
}

// ──────────────────────────────────────────────
// CheckSum
// ──────────────────────────────────────────────

func TestCheckSum(t *testing.T) {
	t.Run("known content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "checksum-test.txt")
		if err := os.WriteFile(path, []byte("hello\n"), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := CheckSum(md5.New(), path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// md5 of "hello\n" is b1946ac92492d2347c6235b4d2611184
		want := "b1946ac92492d2347c6235b4d2611184"
		if got != want {
			t.Errorf("CheckSum = %q, want %q", got, want)
		}
	})
	t.Run("non-existent file", func(t *testing.T) {
		_, err := CheckSum(md5.New(), "/nonexistent/file/xyz123.txt")
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
	})
}

// ──────────────────────────────────────────────
// BuildOutputHeader
// ──────────────────────────────────────────────

func TestBuildOutputHeader(t *testing.T) {
	t.Run("with timestamps", func(t *testing.T) {
		timestamps := []string{"2026-02-10 12:00", "2026-02-10 12:05"}
		infos := map[string]string{"Total requests": "100"}
		got := BuildOutputHeader("test.log", "20260210_120500", timestamps, infos)
		if !contains(got, "the time between 2026-02-10 12:00 and 2026-02-10 12:05") {
			t.Errorf("header missing time range, got: %s", got)
		}
		if !contains(got, "test.log") {
			t.Errorf("header missing filename, got: %s", got)
		}
		if !contains(got, "Total requests") {
			t.Errorf("header missing infos, got: %s", got)
		}
	})
	t.Run("without timestamps", func(t *testing.T) {
		got := BuildOutputHeader("test.log", "20260210_120500", nil, map[string]string{})
		if contains(got, "the time between") {
			t.Errorf("header should not contain time range, got: %s", got)
		}
		if !contains(got, "We analyzed") {
			t.Errorf("header missing 'We analyzed', got: %s", got)
		}
	})
	t.Run("with infos", func(t *testing.T) {
		infos := map[string]string{"key1": "val1", "key2": "val2"}
		got := BuildOutputHeader("test.log", "20260210_120500", nil, infos)
		if !contains(got, "key1") || !contains(got, "val1") {
			t.Errorf("header missing info entries, got: %s", got)
		}
	})
	t.Run("without infos", func(t *testing.T) {
		got := BuildOutputHeader("test.log", "20260210_120500", nil, map[string]string{})
		if !contains(got, "test.log") {
			t.Errorf("header missing filename, got: %s", got)
		}
	})
}

// contains is a small test helper for substring matching.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
