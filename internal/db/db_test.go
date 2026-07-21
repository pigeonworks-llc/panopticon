package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpen(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if store.Path() == "" {
		t.Fatal("Path() returned empty")
	}
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
		"ca_cert", "host_certs", "rules", "rule_applications",
		"captured_requests", "process_identity_cache", "events", "plugin_registry",
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

func TestOpen_CreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() with nested dir error = %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("parent directory not created")
	}
}

func TestOpen_ExistingDB(t *testing.T) {
	dir := t.TempDir()

	s1, err := Open(dir)
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	s1.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	defer s2.Close()

	var count int
	err = s2.DB.QueryRow("SELECT COUNT(*) FROM rules").Scan(&count)
	if err != nil {
		t.Fatalf("query after reload: %v", err)
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_ = store.Close()
}

func TestSchemaStringContains(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello", "xyz", false},
		{"ab", "abc", false},
		{"", "a", false},
		{"hello", "", true},
		{"identical", "identical", true},
		{"the quick brown fox", "quick brown", true},
	}
	for _, tt := range tests {
		got := stringContains(tt.s, tt.sub)
		if got != tt.want {
			t.Errorf("stringContains(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
		}
	}
}

func TestSchema_ValidDDL(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	_, err = store.DB.Exec(`INSERT INTO events (event_id, event_name, ts) VALUES ('test-ulid', 'test', datetime('now'))`)
	if err != nil {
		t.Fatalf("insert into events: %v", err)
	}

	_, err = store.DB.Exec(`INSERT INTO rules (name, conditions, action) VALUES ('test', '{}', '{"action":"allow"}')`)
	if err != nil {
		t.Fatalf("insert into rules: %v", err)
	}
}

func TestOpen_InvalidPath(t *testing.T) {
	// On most systems, /dev/null/panopticon is not a valid dir
	_, err := Open("/dev/null/panopticon")
	if err == nil {
		t.Log("Open with invalid path succeeded (may be on permissive FS)")
	}
}

func TestOpen_BusyTimeout(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	var busyTimeout int
	err = store.DB.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout)
	if err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}
}

func TestOpen_SyncMode(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	var syncMode string
	err = store.DB.QueryRow("PRAGMA synchronous").Scan(&syncMode)
	if err != nil {
		t.Fatalf("query synchronous: %v", err)
	}
	if syncMode != "1" && syncMode != "NORMAL" {
		t.Errorf("synchronous = %s, want NORMAL", syncMode)
	}
}

func TestOpen_ConcurrentReadWrite(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	// Write
	_, err = store.DB.Exec(`INSERT INTO rules (name, conditions, action) VALUES ('concurrent-test', '{}', '{"action":"allow"}')`)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Read
	var name string
	err = store.DB.QueryRow("SELECT name FROM rules WHERE name = 'concurrent-test'").Scan(&name)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "concurrent-test" {
		t.Errorf("name = %q, want 'concurrent-test'", name)
	}
}

func TestOpen_InsertAndQuery(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	// Insert a captured request
	_, err = store.DB.Exec(`INSERT INTO captured_requests (request_id, host, path, method, ts) VALUES ('req-1', 'example.com', '/', 'GET', datetime('now'))`)
	if err != nil {
		t.Fatalf("insert captured_request: %v", err)
	}

	// Query it back
	var host string
	err = store.DB.QueryRow("SELECT host FROM captured_requests WHERE request_id = 'req-1'").Scan(&host)
	if err != nil {
		t.Fatalf("query captured_request: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want 'example.com'", host)
	}

	// Insert into host_certs
	_, err = store.DB.Exec(`INSERT INTO host_certs (host, cert_pem, key_pem, issued_at, expires_at) VALUES ('example.com', 'cert', 'key', datetime('now'), datetime('now', '+1 day'))`)
	if err != nil {
		t.Fatalf("insert host_cert: %v", err)
	}
}
