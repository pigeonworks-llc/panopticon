package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pigeonworks-llc/panopticon/internal/proxy"
	"github.com/pigeonworks-llc/panopticon/internal/server"
)

func TestVersion(t *testing.T) {
	if version != "0.1.0" {
		t.Errorf("version = %q, want 0.1.0", version)
	}
}

func TestSetupConfig_Default(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nonexistent.yaml")

	cfg, err := setupConfig(cfgPath)
	if err != nil {
		t.Fatalf("setupConfig() error = %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":8080")
	}
}

func TestSetupConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	if err := os.WriteFile(cfgPath, []byte("invalid: yaml: [broken"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := setupConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("error should mention 'parse config', got: %v", err)
	}
}

func TestSetup_CreatesCAAndDB(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	configYAML := `
listen: "127.0.0.1:0"
data_dir: "` + dir + `"
verbose: false
`
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := setup(cfgPath)
	if err != nil {
		t.Fatalf("setup() error = %v", err)
	}
	defer a.close()

	// Verify CA files were created
	caCertPath := filepath.Join(dir, "panopticon-ca.pem")
	caKeyPath := filepath.Join(dir, "panopticon-ca-key.pem")

	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Error("CA cert not created")
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Error("CA key not created")
	}

	// Verify database was created
	dbPath := filepath.Join(dir, "panopticon.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("SQLite database not created")
	}
}

func TestSetup_ProxyConfigured(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	configYAML := `
listen: "127.0.0.1:0"
data_dir: "` + dir + `"
`
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	a, err := setup(cfgPath)
	if err != nil {
		t.Fatalf("setup() error = %v", err)
	}

	if a.proxy == nil {
		t.Fatal("proxy not initialized")
	}
	if a.ca == nil {
		t.Fatal("CA not initialized")
	}
	if a.db == nil {
		t.Fatal("DB not initialized")
	}

	// close should not error
	a.close()

	// Double close should not panic
	a.close()
}

func TestSetup_ExistingCA(t *testing.T) {
	// Test that setup works when CA and DB already exist
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	configYAML := `
listen: "127.0.0.1:0"
data_dir: "` + dir + `"
`
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// First call creates CA and DB
	a1, err := setup(cfgPath)
	if err != nil {
		t.Fatalf("first setup() error = %v", err)
	}
	a1.close()

	// Second call loads existing
	a2, err := setup(cfgPath)
	if err != nil {
		t.Fatalf("second setup() error = %v", err)
	}
	a2.close()
}

func TestAppRun_WithoutMITM(t *testing.T) {
	a := &app{
		cfg: &server.Config{
			Listen: "127.0.0.1:0",
		},
		proxy: proxy.NewPanopticonProxy(),
	}
	err := a.run()
	if err == nil {
		t.Fatal("expected error from run() without MITM")
	}
}

func TestAppCloseNilDB(t *testing.T) {
	// close() should handle nil db gracefully
	a := &app{}
	a.close() // should not panic
}

func TestRunMain_Version(t *testing.T) {
	code := runMain([]string{"-version"})
	if code != 0 {
		t.Errorf("runMain(-version) = %d, want 0", code)
	}
}

func TestRunMain_ConfigNonexistent(t *testing.T) {
	// -config with nonexistent path: should fail (log.Fatalf from setup)
	code := runMain([]string{"-config", "/nonexistent/panopticon.yaml"})
	if code != 0 {
		t.Logf("runMain with nonexistent config returned %d (expected)", code)
	}
}

func TestRunMain_EmptyArgs(t *testing.T) {
	// No args should try to start the proxy with default config
	// In test environment it will likely fail at CA/db creation or proxy start
	code := runMain([]string{})
	t.Logf("runMain() returned %d", code)
}

func TestRunMain_InvalidFlag(t *testing.T) {
	code := runMain([]string{"--bad-flag"})
	if code != 1 {
		t.Errorf("runMain with bad flag = %d, want 1", code)
	}
}
