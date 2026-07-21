package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

const hostCertTTL = 24 * time.Hour

// SignHostCert signs a certificate for the given hostnames/IPs using the CA.
// It returns the certificate PEM, key PEM, and any error.
func (c *CA) SignHostCert(hosts ...string) (certPEM, keyPEM []byte, err error) {
	// Generate ephemeral key for this host cert
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate host key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hosts[0],
			Organization: []string{"Panopticon MITM Proxy"},
		},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(hostCertTTL),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &hostKey.PublicKey, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("create host cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(hostKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal host key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// hostPortToHostname strips the port from a host:port string.
// If there's no port, it returns the input unchanged.
func hostPortToHostname(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port, strip IPv6 brackets if present
		return strings.Trim(hostport, "[]")
	}
	return host
}

// isPort checks if the given string could be a valid port number.
func isPort(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p < 65536
}
