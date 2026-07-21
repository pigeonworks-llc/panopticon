package proxy

import (
	"testing"

	"github.com/pigeonworks-llc/panopticon/internal/certauth"
)

func TestNewPanopticonProxy(t *testing.T) {
	p := NewPanopticonProxy()
	if p == nil {
		t.Fatal("NewPanopticonProxy() returned nil")
	}
}

func TestProxy_SetCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := certauth.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	p := NewPanopticonProxy()
	if p == nil {
		t.Fatal("NewPanopticonProxy() returned nil")
	}

	if err := p.SetCA(ca); err != nil {
		t.Fatalf("SetCA() error = %v", err)
	}

	if !p.mitmEnabled {
		t.Fatal("MITM should be enabled after SetCA")
	}
}
