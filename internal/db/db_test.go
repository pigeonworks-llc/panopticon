package db

import (
	"testing"
)

func TestOpen(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
}

func TestOpen_WALMode(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	var journalMode string
	err = store.DB.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %s, want wal", journalMode)
	}
}

func TestOpen_ForeignKeys(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	var fkEnabled int
	err = store.DB.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	if err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fkEnabled != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fkEnabled)
	}
}

func TestOpen_TablesExist(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	tables := []string{
		"ca_cert",
		"host_certs",
		"rules",
		"rule_applications",
		"captured_requests",
		"process_identity_cache",
		"events",
		"plugin_registry",
	}

	for _, table := range tables {
		var count int
		err := store.DB.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&count)
		if err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %s not found", table)
		}
	}
}
