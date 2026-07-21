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

func main() {
	configPath := flag.String("config", "", "Path to config file (default: ~/.config/panopticon/panopticon.yaml)")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("panopticon v%s\n", version)
		os.Exit(0)
	}

	// Resolve config path
	cfgPath := *configPath
	if cfgPath == "" {
		cfgDir := server.DefaultConfigDir()
		cfgPath = filepath.Join(cfgDir, "panopticon.yaml")
	}

	// Load configuration
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Ensure CA certificate exists
	dataDir := cfg.ResolveDataDir()
	ca, err := certauth.EnsureCA(dataDir)
	if err != nil {
		log.Fatalf("setup CA: %v", err)
	}
	log.Printf("CA certificate ready: %s", filepath.Join(dataDir, "panopticon-ca.pem"))

	// Open database
	store, err := db.Open(dataDir)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()
	log.Printf("Database: %s", store.Path())

	// Create proxy
	p := proxy.NewPanopticonProxy()
	if err := p.SetCA(ca); err != nil {
		log.Fatalf("setup MITM: %v", err)
	}
	p.SetVerbose(cfg.Verbose)

	log.Printf("Panopticon v%s starting on %s", version, cfg.Listen)
	log.Printf("Trust CA cert: security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
		filepath.Join(dataDir, "panopticon-ca.pem"))

	if err := p.Start(cfg.Listen); err != nil {
		log.Fatalf("proxy failed: %v", err)
	}
}
