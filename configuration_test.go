package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ──────────────────────────────────────────────
// setDefaults
// ──────────────────────────────────────────────

func TestSetDefaults(t *testing.T) {
	var cfg ApplicationConfig
	cfg.setDefaults()

	if cfg.DateLayout != "02/Jan/2006:15:04:05 -0700" {
		t.Errorf("DateLayout: got %q, want %q", cfg.DateLayout, "02/Jan/2006:15:04:05 -0700")
	}
	if cfg.OutputFolder != "./output/" {
		t.Errorf("OutputFolder: got %q, want %q", cfg.OutputFolder, "./output/")
	}
	if cfg.LogType != "apache" {
		t.Errorf("LogType: got %q, want %q", cfg.LogType, "apache")
	}
	if cfg.LogFormat != `%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"` {
		t.Errorf("LogFormat: got %q", cfg.LogFormat)
	}
	if cfg.Logcfg.LogLevel != "INFO" {
		t.Errorf("LogLevel: got %q, want %q", cfg.Logcfg.LogLevel, "INFO")
	}
	if cfg.Logcfg.LogFolder != "./logs/" {
		t.Errorf("LogFolder: got %q, want %q", cfg.Logcfg.LogFolder, "./logs/")
	}
}

// ──────────────────────────────────────────────
// Initialize
// ──────────────────────────────────────────────

func TestInitializeValidYAML(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs") + "/"
	outDir := filepath.Join(dir, "output") + "/"
	os.MkdirAll(logDir, 0750)
	os.MkdirAll(outDir, 0750)

	yamlContent := `DateLayout: "02/Jan/2006:15:04:05 -0700"
OutputFolder: "` + outDir + `"
LogType: "rosetta"
LogConfig:
  LogLevel: "Debug"
  LogFolder: "` + logDir + `"
`
	cfgFile := filepath.Join(dir, "topFive.yml")
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	var cfg ApplicationConfig
	cfg.Initialize(&cfgFile)

	if cfg.LogType != "rosetta" {
		t.Errorf("LogType: got %q, want %q", cfg.LogType, "rosetta")
	}
	if cfg.Logcfg.LogLevel != "Debug" {
		t.Errorf("LogLevel: got %q, want %q", cfg.Logcfg.LogLevel, "Debug")
	}
	if cfg.OutputFolder != outDir {
		t.Errorf("OutputFolder: got %q, want %q", cfg.OutputFolder, outDir)
	}
}

func TestInitializeMissingFile(t *testing.T) {
	dir := t.TempDir()
	// Pre-create the default dirs that CheckConfig will check
	os.MkdirAll(filepath.Join(dir, "logs"), 0750)
	os.MkdirAll(filepath.Join(dir, "output"), 0750)

	// Use a config that points to directories that exist via setDefaults override
	// Since the file is missing, it falls back to defaults.
	// We need to chdir so the default relative paths (./logs/, ./output/) resolve.
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	missing := filepath.Join(dir, "nonexistent.yml")
	var cfg ApplicationConfig
	cfg.Initialize(&missing)

	// Should have defaults
	if cfg.LogType != "apache" {
		t.Errorf("LogType: got %q, want default %q", cfg.LogType, "apache")
	}
	if cfg.DateLayout != "02/Jan/2006:15:04:05 -0700" {
		t.Errorf("DateLayout: got %q, want default", cfg.DateLayout)
	}
}

func TestInitializePartialYAML(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs") + "/"
	outDir := filepath.Join(dir, "output") + "/"
	os.MkdirAll(logDir, 0750)
	os.MkdirAll(outDir, 0750)

	// Only set LogType; other fields should keep defaults
	yamlContent := `LogType: "logfmt"
OutputFolder: "` + outDir + `"
LogConfig:
  LogFolder: "` + logDir + `"
`
	cfgFile := filepath.Join(dir, "partial.yml")
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	var cfg ApplicationConfig
	cfg.Initialize(&cfgFile)

	if cfg.LogType != "logfmt" {
		t.Errorf("LogType: got %q, want %q", cfg.LogType, "logfmt")
	}
	// DateLayout should still be the default
	if cfg.DateLayout != "02/Jan/2006:15:04:05 -0700" {
		t.Errorf("DateLayout: got %q, want default", cfg.DateLayout)
	}
}

// ──────────────────────────────────────────────
// CheckConfig
// ──────────────────────────────────────────────

func TestCheckConfigTrailingSlashes(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	outDir := filepath.Join(dir, "output")
	os.MkdirAll(logDir, 0750)
	os.MkdirAll(outDir, 0750)

	cfg := ApplicationConfig{
		OutputFolder: outDir, // no trailing slash
		Logcfg: LogConfig{
			LogFolder: logDir, // no trailing slash
		},
	}
	cfg.CheckConfig()

	if cfg.OutputFolder != outDir+"/" {
		t.Errorf("OutputFolder: got %q, want trailing slash", cfg.OutputFolder)
	}
	if cfg.Logcfg.LogFolder != logDir+"/" {
		t.Errorf("LogFolder: got %q, want trailing slash", cfg.Logcfg.LogFolder)
	}
}
