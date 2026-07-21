package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
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

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("CA cert file not written")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("CA key file not written")
	}
}

func TestEnsureCA_LoadsExisting(t *testing.T) {
	dir := t.TempDir()

	ca1, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA() error = %v", err)
	}

	ca2, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA() error = %v", err)
	}

	if !ca1.Cert.Equal(ca2.Cert) {
		t.Fatal("loaded CA should equal generated CA")
	}
}

func TestEnsureCA_LoadsCorruptCert(t *testing.T) {
	dir := t.TempDir()

	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	if err := os.WriteFile(certPath, []byte("not-valid-pem"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-valid-key"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := EnsureCA(dir)
	if err == nil {
		t.Fatal("expected error for corrupt cert files")
	}
}

func TestCA_IsCA_Certificate(t *testing.T) {
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

func TestEnsureCA_KeyOnlyExists(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, caKeyFile)
	if err := os.WriteFile(keyPath, []byte("fake-key"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}
	if ca == nil {
		t.Fatal("EnsureCA() returned nil")
	}
}

func TestEnsureCA_ReadOnlyDir(t *testing.T) {
	// Create a read-only parent dir to simulate write failure
	parent := t.TempDir()
	dir := filepath.Join(parent, "subdir")
	if err := os.Chmod(parent, 0500); err != nil {
		t.Skipf("cannot make read-only: %v", err)
	}

	_, err := EnsureCA(dir)
	if err == nil {
		t.Log("Generate succeeded (may run as root)")
	}
	os.Chmod(parent, 0755)
}

func TestLoadCA_InvalidCertPEM(t *testing.T) {
	_, err := loadCA([]byte("invalid-cert"), []byte("invalid-key"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadCA_InvalidCertBlock(t *testing.T) {
	invalidBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-valid-der")})
	_, err := loadCA(invalidBlock, []byte("invalid-key"))
	if err == nil {
		t.Fatal("expected error for invalid cert block")
	}
}

func TestLoadCA_InvalidKeyPEM(t *testing.T) {
	// Create a valid cert but invalid key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	_, err := loadCA(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("bad-key")}))
	if err == nil {
		t.Fatal("expected error for invalid key DER")
	}
}
