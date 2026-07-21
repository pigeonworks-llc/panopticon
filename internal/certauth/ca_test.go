package certauth

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCA_GeneratesNew(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}
	if ca == nil {
		t.Fatal("EnsureCA() returned nil")
	}
	if ca.Cert == nil {
		t.Fatal("ca.Cert is nil")
	}
	if !ca.Cert.IsCA {
		t.Fatal("generated CA should be a CA cert")
	}
	// Verify files were written
	if _, err := os.Stat(filepath.Join(dir, caCertFile)); os.IsNotExist(err) {
		t.Fatal("CA cert file not written")
	}
	if _, err := os.Stat(filepath.Join(dir, caKeyFile)); os.IsNotExist(err) {
		t.Fatal("CA key file not written")
	}
}

func TestEnsureCA_LoadsExisting(t *testing.T) {
	dir := t.TempDir()

	// First call generates
	ca1, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA() error = %v", err)
	}

	// Second call loads
	ca2, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA() error = %v", err)
	}

	if !ca1.Cert.Equal(ca2.Cert) {
		t.Fatal("loaded CA should equal generated CA")
	}
}

func TestCA_IsCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	cert, err := x509.ParseCertificate(ca.Cert.Raw)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if !cert.IsCA {
		t.Fatal("CA cert IsCA should be true")
	}
	if cert.MaxPathLen != 1 {
		t.Fatalf("CA cert MaxPathLen = %d, want 1", cert.MaxPathLen)
	}
}

func TestCA_TLSCertificate(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	certPEM, keyPEM := ca.TLSCertificate()
	if len(certPEM) == 0 {
		t.Fatal("TLSCertificate() returned empty certPEM")
	}
	if len(keyPEM) == 0 {
		t.Fatal("TLSCertificate() returned empty keyPEM")
	}
}
