package certauth

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestSignHostCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	certPEM, keyPEM, err := ca.SignHostCert("example.com")
	if err != nil {
		t.Fatalf("SignHostCert() error = %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("DNSNames = %v, want [example.com]", leaf.DNSNames)
	}

	if leaf.NotBefore.After(time.Now()) {
		t.Fatal("cert NotBefore is in the future")
	}
	if leaf.NotAfter.Before(time.Now()) {
		t.Fatal("cert NotAfter is in the past")
	}
}

func TestSignHostCert_MultipleHosts(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	hosts := []string{"example.com", "www.example.com", "api.example.com", "192.168.1.1"}
	certPEM, keyPEM, err := ca.SignHostCert(hosts...)
	if err != nil {
		t.Fatalf("SignHostCert() error = %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	expectedDNS := []string{"example.com", "www.example.com", "api.example.com"}
	for i, dns := range expectedDNS {
		if leaf.DNSNames[i] != dns {
			t.Fatalf("DNSNames[%d] = %s, want %s", i, leaf.DNSNames[i], dns)
		}
	}

	// Verify IP SAN
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.168.1.1" {
		t.Fatalf("IPAddresses = %v, want [192.168.1.1]", leaf.IPAddresses)
	}
}

func TestSignHostCert_ValidatesWithCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	certPEM, keyPEM, err := ca.SignHostCert("secure.example.com")
	if err != nil {
		t.Fatalf("SignHostCert() error = %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Verify the signed cert is valid with the CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       "secure.example.com",
		Intermediates: x509.NewCertPool(),
	}

	_, err = leaf.Verify(opts)
	if err != nil {
		t.Fatalf("cert verify with CA failed: %v", err)
	}
}

func TestSignHostCert_Wildcard(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}

	certPEM, keyPEM, err := ca.SignHostCert("*.example.com")
	if err != nil {
		t.Fatalf("SignHostCert() error = %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.example.com" {
		t.Fatalf("DNSNames = %v, want [*.example.com]", leaf.DNSNames)
	}

	// Verify wildcard cert works for subdomain
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: "sub.example.com",
	}

	_, err = leaf.Verify(opts)
	if err != nil {
		t.Fatalf("wildcard cert verify failed: %v", err)
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
		{"*.example.com:443", "*.example.com"},
	}
	for _, tt := range tests {
		got := hostPortToHostname(tt.input)
		if got != tt.want {
			t.Errorf("hostPortToHostname(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"example.com", false},
		{"*.example.com", false},
	}
	for _, tt := range tests {
		got := net.ParseIP(tt.input) != nil
		if got != tt.want {
			t.Errorf("net.ParseIP(%q) != nil = %v, want %v", tt.input, got, tt.want)
		}
	}
}
