package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// siteCert makes a self-signed certificate for name and trusts it in roots.
func siteCert(t *testing.T, name string, roots *x509.CertPool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	roots.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestSiteScan runs the search over 127.0.0.0/24 with neighbours of every
// kind the guide had to tell apart by hand.
func TestSiteScan(t *testing.T) {
	l0, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l0.Addr().String())
	l0.Close()
	roots := x509.NewCertPool()
	dns := map[string][]net.IP{}
	serve := func(ip, name string, maxTLS uint16, h2 bool, status int) {
		cfg := &tls.Config{Certificates: []tls.Certificate{siteCert(t, name, roots)}, MaxVersion: maxTLS, NextProtos: []string{"http/1.1"}}
		if h2 {
			cfg.NextProtos = []string{"h2", "http/1.1"}
		}
		l, err := tls.Listen("tcp", net.JoinHostPort(ip, port), cfg)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status == 301 {
				http.Redirect(w, r, "https://elsewhere.test/", 301)
				return
			}
			fmt.Fprint(w, "site")
		})}
		srv.TLSConfig = cfg
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
	}
	serve("127.0.0.10", "good.test", 0, true, 200)
	dns["good.test"] = []net.IP{net.ParseIP("127.0.0.10")}
	serve("127.0.0.11", "redir.test", 0, true, 301)
	dns["redir.test"] = []net.IP{net.ParseIP("127.0.0.11")}
	serve("127.0.0.12", "old.test", tls.VersionTLS12, true, 200) // no TLS 1.3
	dns["old.test"] = []net.IP{net.ParseIP("127.0.0.12")}
	serve("127.0.0.13", "h1.test", 0, false, 200) // no HTTP/2
	dns["h1.test"] = []net.IP{net.ParseIP("127.0.0.13")}
	serve("127.0.0.14", "cdn.test", 0, true, 200) // its DNS points away: not a neighbour
	dns["cdn.test"] = []net.IP{net.ParseIP("203.0.113.9")}

	s := &siteScanner{port: port, roots: roots, timeout: 2 * time.Second, resolve: func(_ context.Context, h string) ([]net.IP, error) {
		if ips, ok := dns[h]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("no such host %s", h)
	}}
	st := &scanState{scanResult: scanResult{Running: true}}
	s.run(st, net.ParseIP("127.0.0.1"))
	got := st.snapshot()
	if got.Running || got.Done != 254 || got.Net != "127.0.0.0/24" {
		t.Fatalf("%+v", got)
	}
	var names []string
	for _, c := range got.Found {
		names = append(names, fmt.Sprintf("%s/%d/%v", c.Domain, c.Status, c.SameIP))
	}
	// 200 before the redirect; TLS 1.2, HTTP/1-only and far-away sites are out.
	if len(got.Found) != 2 || got.Found[0].Domain != "good.test" || got.Found[0].Status != 200 || !got.Found[0].SameIP ||
		got.Found[1].Domain != "redir.test" || got.Found[1].Status != 301 {
		t.Fatalf("%v", names)
	}
}
