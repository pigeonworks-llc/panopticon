// Package db provides SQLite database management for Panopticon.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database connection.
type Store struct {
	DB   *sql.DB
	path string
}

// Open opens or creates the Panopticon database at the given data directory.
// It runs schema migrations and configures WAL mode.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "panopticon.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode and foreign keys
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("set pragma %s: %w", p, err)
		}
	}

	// Run schema
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{DB: db, path: dbPath}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.DB.Close()
}

// Path returns the filesystem path to the database file.
func (s *Store) Path() string {
	return s.path
}
