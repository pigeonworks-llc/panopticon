// Package server provides configuration management for Panopticon.
package server

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	defaultListen  = ":8080"
	defaultDataDir = "~/.local/share/panopticon"
)

// Config is the top-level configuration structure.
type Config struct {
	Listen  string       `yaml:"listen"`
	DataDir string       `yaml:"data_dir"`
	Verbose bool         `yaml:"verbose"`
	Rules   []RuleConfig `yaml:"rules"`
}

// RuleConfig defines a single rule in the configuration.
type RuleConfig struct {
	Name       string         `yaml:"name"`
	Priority   int            `yaml:"priority"`
	Enabled    bool           `yaml:"enabled"`
	Conditions []ConditionDef `yaml:"conditions"`
	Action     ActionDef      `yaml:"action"`
	Notes      string         `yaml:"notes"`
}

// ConditionDef defines a matching condition for a rule.
type ConditionDef struct {
	Type     string `yaml:"type"`      // host, path, method, header, process, any
	Host     string `yaml:"host"`      // for type=host
	Path     string `yaml:"path"`      // for type=path
	Method   string `yaml:"method"`    // for type=method
	Key      string `yaml:"key"`       // for type=header
	Value    string `yaml:"value"`     // for type=header
	BundleID string `yaml:"bundle_id"` // for type=process
}

// ActionDef defines what action to take when a rule matches.
type ActionDef struct {
	Action string         `yaml:"action"` // allow, deny, log, mask
	Config map[string]any `yaml:"config"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Listen:  defaultListen,
		DataDir: defaultDataDir,
		Verbose: false,
		Rules:   nil,
	}
}

// LoadConfig loads configuration from a YAML file.
// If the file doesn't exist, it returns default configuration.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Apply defaults for zero-value fields
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.DataDir == "" {
		cfg.DataDir = defaultDataDir
	}

	return cfg, nil
}

// DefaultConfigDir returns the default configuration directory.
func DefaultConfigDir() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "panopticon")
}

// ResolveDataDir expands ~ in the data directory path.
// If DataDir is empty, it returns the default data directory.
func (c *Config) ResolveDataDir() string {
	dd := c.DataDir
	if dd == "" {
		dd = defaultDataDir
	}
	if len(dd) > 0 && dd[0] == '~' {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, dd[1:])
	}
	return dd
}
