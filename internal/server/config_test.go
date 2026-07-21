package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "panopticon.yaml")
	// Don't write config - should use defaults

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

func TestDefaultConfigPath(t *testing.T) {
	dir := DefaultConfigDir()
	if dir == "" {
		t.Fatal("DefaultConfigDir() returned empty")
	}
}
