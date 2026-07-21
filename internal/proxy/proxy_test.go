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

func TestProxy_StartWithoutCA(t *testing.T) {
	p := NewPanopticonProxy()
	err := p.Start(":0")
	if err == nil {
		t.Fatal("expected error starting without CA")
	}
}

func TestHostPortToHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:443", "::1"},
	}
	for _, tt := range tests {
		got := hostPortToHostname(tt.input)
		if got != tt.want {
			t.Errorf("hostPortToHostname(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUpstreamTransport(t *testing.T) {
	tr := upstreamTransport()
	if tr == nil {
		t.Fatal("upstreamTransport() returned nil")
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout should be set")
	}
}

func TestSetVerbose(t *testing.T) {
	p := NewPanopticonProxy()
	p.SetVerbose(true)
	if !p.Proxy.Verbose {
		t.Error("SetVerbose(true) should enable verbose")
	}
	p.SetVerbose(false)
	if p.Proxy.Verbose {
		t.Error("SetVerbose(false) should disable verbose")
	}
}

func TestSetCA_MultipleCalls(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	ca1, err := certauth.EnsureCA(dir1)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}
	ca2, err := certauth.EnsureCA(dir2)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	p := NewPanopticonProxy()
	if err := p.SetCA(ca1); err != nil {
		t.Fatalf("first SetCA() error = %v", err)
	}
	if !p.mitmEnabled {
		t.Fatal("MITM should be enabled after first SetCA")
	}
	// Re-setting CA should work
	if err := p.SetCA(ca2); err != nil {
		t.Fatalf("second SetCA() error = %v", err)
	}
}

func TestNewAndStart(t *testing.T) {
	p := NewPanopticonProxy()
	if p.Proxy.Logger == nil {
		t.Error("Logger should not be nil")
	}
}
