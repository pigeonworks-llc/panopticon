package db

import (
	"testing"
)

func TestSchema_ContainsRequiredTables(t *testing.T) {
	requiredTables := []string{
		"ca_cert",
		"host_certs",
		"rules",
		"rule_applications",
		"captured_requests",
		"process_identity_cache",
		"events",
		"plugin_registry",
	}

	for _, table := range requiredTables {
		if !stringContains(Schema, table) {
			t.Errorf("schema missing table: %s", table)
		}
	}
}

func TestSchema_ContainsWAL(t *testing.T) {
	if !stringContains(Schema, "WAL") {
		t.Error("schema missing WAL pragma")
	}
}

func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
