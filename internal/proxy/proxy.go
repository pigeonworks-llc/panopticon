// Package proxy provides the core MITM proxy functionality.
package proxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/pigeonworks-llc/panopticon/internal/certauth"
)

// PanopticonProxy wraps goproxy with MITM capabilities and rule engine.
type PanopticonProxy struct {
	Proxy       *goproxy.ProxyHttpServer
	CA          *certauth.CA
	mitmEnabled bool
}

// NewPanopticonProxy creates a new proxy instance.
func NewPanopticonProxy() *PanopticonProxy {
	p := &PanopticonProxy{
		Proxy: goproxy.NewProxyHttpServer(),
	}

	p.Proxy.Verbose = false
	p.Proxy.Logger = log.Default()

	return p
}

// SetCA installs the CA certificate and enables MITM for all CONNECT requests.
func (p *PanopticonProxy) SetCA(ca *certauth.CA) error {
	p.CA = ca

	// Convert CA PEM to tls.Certificate for goproxy's global CA
	tlsCert, err := tls.X509KeyPair(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		return fmt.Errorf("build tls.Certificate from CA: %w", err)
	}
	goproxy.GoproxyCa = tlsCert

	// Enable MITM for all CONNECT requests using goproxy's built-in signer
	// (automatically generates per-host certs signed by GoproxyCa)
	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.mitmEnabled = true
	return nil
}

// SetVerbose controls verbose logging on the proxy.
func (p *PanopticonProxy) SetVerbose(v bool) {
	p.Proxy.Verbose = v
}

// Start begins listening on the given address (e.g. ":8080").
// Blocks until the server stops.
func (p *PanopticonProxy) Start(addr string) error {
	if !p.mitmEnabled {
		return fmt.Errorf("MITM not enabled — call SetCA first")
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      p.Proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Panopticon proxy listening on %s", addr)
	return server.ListenAndServe()
}

// hostPortToHostname strips the port from a host:port string.
func hostPortToHostname(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// upstreamTransport returns a default HTTP transport for upstream connections.
func upstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// Ensure url is used
var _ = url.URL{}
