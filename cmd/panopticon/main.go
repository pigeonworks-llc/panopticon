// Panopticon — AI-native HTTPS Control & Analysis Proxy.
//
// Usage:
//
//	panopticon                    # Start proxy with default config
//	panopticon -config <path>     # Start with explicit config
//	panopticon -version           # Show version
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/pigeonworks-llc/panopticon/internal/certauth"
	"github.com/pigeonworks-llc/panopticon/internal/db"
	"github.com/pigeonworks-llc/panopticon/internal/proxy"
	"github.com/pigeonworks-llc/panopticon/internal/server"
)

const version = "0.1.0"

// app holds the initialized proxy components. Created by setup().
type app struct {
	cfg   *server.Config
	ca    *certauth.CA
	db    *db.Store
	proxy *proxy.PanopticonProxy
}

// setupConfig loads configuration from the given path.
func setupConfig(configPath string) (*server.Config, error) {
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// setup initializes all proxy components (config, CA, DB, proxy) without
// starting the listener. This is safe to call in tests.
func setup(configPath string) (*app, error) {
	cfg, err := setupConfig(configPath)
	if err != nil {
		return nil, err
	}

	dataDir := cfg.ResolveDataDir()

	ca, err := certauth.EnsureCA(dataDir)
	if err != nil {
		return nil, fmt.Errorf("setup CA: %w", err)
	}
	log.Printf("CA certificate ready: %s", filepath.Join(dataDir, "panopticon-ca.pem"))

	store, err := db.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	log.Printf("Database: %s", store.Path())

	p := proxy.NewPanopticonProxy()
	if err := p.SetCA(ca); err != nil {
		store.Close()
		return nil, fmt.Errorf("setup MITM: %w", err)
	}
	p.SetVerbose(cfg.Verbose)

	return &app{
		cfg:   cfg,
		ca:    ca,
		db:    store,
		proxy: p,
	}, nil
}

// close cleans up app resources.
func (a *app) close() {
	if a.db != nil {
		a.db.Close()
	}
}

// run starts the proxy and blocks until the server stops.
func (a *app) run() error {
	defer a.close()

	log.Printf("Panopticon v%s starting on %s", version, a.cfg.Listen)
	log.Printf("Trust CA cert: security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
		filepath.Join(a.cfg.ResolveDataDir(), "panopticon-ca.pem"))

	return a.proxy.Start(a.cfg.Listen)
}

func main() {
	os.Exit(runMain(os.Args[1:]))
}

// runMain encapsulates the CLI logic for testability.
// Returns an exit code. Uses its own FlagSet, never calls os.Exit or log.Fatal.
func runMain(args []string) int {
	fs := flag.NewFlagSet("panopticon", flag.ContinueOnError)
	configPath := fs.String("config", "", "Path to config file (default: ~/.config/panopticon/panopticon.yaml)")
	showVersion := fs.Bool("version", false, "Show version")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "panopticon: %v\n", err)
		return 1
	}

	if *showVersion {
		fmt.Printf("panopticon v%s\n", version)
		return 0
	}

	cfgPath := *configPath
	if cfgPath == "" {
		cfgDir := server.DefaultConfigDir()
		cfgPath = filepath.Join(cfgDir, "panopticon.yaml")
	}

	a, err := setup(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "panopticon: setup: %v\n", err)
		return 1
	}

	if err := a.run(); err != nil {
		fmt.Fprintf(os.Stderr, "panopticon: proxy: %v\n", err)
		return 1
	}

	return 0
}
