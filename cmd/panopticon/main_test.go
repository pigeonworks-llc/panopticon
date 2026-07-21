package main

import (
	"testing"
)

func TestVersion(t *testing.T) {
	if version != "0.1.0" {
		t.Errorf("version = %q, want 0.1.0", version)
	}
}
