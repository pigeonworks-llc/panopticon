package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":8080")
	}
	if cfg.DataDir != defaultDataDir {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, defaultDataDir)
	}
	if cfg.Verbose != false {
		t.Errorf("Verbose = %v, want false", cfg.Verbose)
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	configYAML := `
listen: ":9090"
data_dir: "/tmp/panop-test"
verbose: true
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Listen != ":9090" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":9090")
	}
	if cfg.Verbose != true {
		t.Errorf("Verbose = %v, want true", cfg.Verbose)
	}
}

func TestLoadConfig_WithRules(t *testing.T) {
	configYAML := `
listen: ":8080"
rules:
  - name: "block-test"
    priority: 100
    conditions:
      - type: host
        value: "evil.example.com"
    action:
      action: deny
      config:
        response_code: 403
        response_body: "Blocked"
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(cfg.Rules))
	}

	rule := cfg.Rules[0]
	if rule.Name != "block-test" {
		t.Errorf("Rule.Name = %q, want %q", rule.Name, "block-test")
	}
	if len(rule.Conditions) != 1 {
		t.Fatalf("len(Rule.Conditions) = %d, want 1", len(rule.Conditions))
	}
	if rule.Conditions[0].Value != "evil.example.com" {
		t.Errorf("Condition.Value = %q, want %q", rule.Conditions[0].Value, "evil.example.com")
	}
	if rule.Action.Action != "deny" {
		t.Errorf("Rule.Action = %q, want %q", rule.Action.Action, "deny")
	}
}

func TestLoadConfig_WithMultipleRules(t *testing.T) {
	configYAML := `
rules:
  - name: "first"
    priority: 10
    conditions:
      - type: host
        value: "allowed.example.com"
    action:
      action: allow
  - name: "second"
    priority: 20
    conditions:
      - type: path
        value: "/api/*"
    action:
      action: deny
  - name: "third"
    priority: 9999
    conditions:
      - type: any
    action:
      action: log
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if len(cfg.Rules) != 3 {
		t.Fatalf("len(Rules) = %d, want 3", len(cfg.Rules))
	}

	if cfg.Rules[0].Action.Action != "allow" {
		t.Errorf("first rule action = %q, want allow", cfg.Rules[0].Action.Action)
	}
	if cfg.Rules[1].Conditions[0].Type != "path" {
		t.Errorf("second rule condition type = %q, want path", cfg.Rules[1].Conditions[0].Type)
	}
	if cfg.Rules[2].Conditions[0].Type != "any" {
		t.Errorf("third rule condition type = %q, want any", cfg.Rules[2].Conditions[0].Type)
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":8080")
	}
}

func TestLoadConfig_PartialFile(t *testing.T) {
	configYAML := `
verbose: true
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen should be default, got %q", cfg.Listen)
	}
	if cfg.Verbose != true {
		t.Errorf("Verbose = %v, want true", cfg.Verbose)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":8080")
	}
}

func TestDefaultConfigDir(t *testing.T) {
	dir := DefaultConfigDir()
	if dir == "" {
		t.Fatal("DefaultConfigDir() returned empty")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("DefaultConfigDir() = %q, should be absolute", dir)
	}
}

func TestResolveDataDir_Tilde(t *testing.T) {
	cfg := &Config{
		DataDir: "~/custom/panop",
	}
	dir := cfg.ResolveDataDir()
	if dir == "~/custom/panop" {
		t.Errorf("ResolveDataDir() should expand ~, got %q", dir)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("ResolveDataDir() = %q, should be absolute after expansion", dir)
	}
}

func TestResolveDataDir_Absolute(t *testing.T) {
	cfg := &Config{
		DataDir: "/var/lib/panopticon",
	}
	dir := cfg.ResolveDataDir()
	if dir != "/var/lib/panopticon" {
		t.Errorf("ResolveDataDir() = %q, want %q", dir, "/var/lib/panopticon")
	}
}

func TestResolveDataDir_Empty(t *testing.T) {
	cfg := &Config{}
	dir := cfg.ResolveDataDir()
	// Empty DataDir expands to ~/.local/share/panopticon
	if dir == "" {
		t.Fatal("ResolveDataDir() should expand empty DataDir to default")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadConfig() for missing file should not error, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig() returned nil for missing file")
	}
}
