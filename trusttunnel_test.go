package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The installed release is optional, as for the Xray and AmneziaWG checks.
func TestTrustTunnelNative(t *testing.T) {
	bin := os.Getenv("HYP_TEST_TRUSTTUNNEL")
	if bin == "" {
		t.Skip("set HYP_TEST_TRUSTTUNNEL to trusttunnel_endpoint")
	}
	listen := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	tunnel, metrics := listen(), listen()
	tunnelAddr, metricsAddr := tunnel.Addr().String(), metrics.Addr().String()
	tunnel.Close()
	metrics.Close()
	_, port, _ := net.SplitHostPort(tunnelAddr)
	c := trustTunnelConfig{Domain: "vpn.example.com", Port: port}
	cert, key, err := trustTunnelCertificate(c.Domain)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert)
	c.cert = block.Bytes
	dir := t.TempDir()
	put := func(name string, data []byte) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, data, 0600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	u := User{Name: "phone", UUID: "2755d569-324d-4f73-8c5f-0f364e61e04a", SubToken: "test-sub-token"}
	creds := put("credentials.toml", trustTunnelCredentials([]trustTunnelUser{{u.Name, trustTunnelPassword(u)}}))
	vpn := put("vpn.toml", trustTunnelVPNConfig(port, creds, metricsAddr))
	hosts := put("hosts.toml", trustTunnelHostsConfig(c.Domain, put("cert.pem", cert), put("key.pem", key)))
	ep := Endpoint{TrustTunnel: &c}
	export := exec.Command(bin, vpn, hosts, "-c", u.Name, "-a", c.address(), "--name", (trustTunnelProto{}).ProxyName(ep, u))
	out, err := export.CombinedOutput()
	if err != nil {
		t.Fatalf("native export: %v\n%s", err, out)
	}
	var nativeLink string
	for _, line := range strings.Fields(string(out)) {
		if strings.HasPrefix(line, "tt://?") {
			nativeLink = line
			break
		}
	}
	decode := func(link string) []byte {
		payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "tt://?"))
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	nativePayload := decode(nativeLink)
	panelPayload := decode(ep.Link(protoTrustTunnel, u))
	// Upstream CLI always advertises IPv6. The panel explicitly disables it.
	certTag := bytes.Index(panelPayload, c.cert) - 3
	if certTag < 3 || !bytes.Equal(panelPayload[certTag-3:certTag], []byte{0x04, 1, 0}) ||
		!bytes.Equal(append(panelPayload[:certTag-3:certTag-3], panelPayload[certTag:]...), nativePayload) {
		t.Fatalf("deep link differs from upstream export beyond the IPv6 flag (%d vs %d bytes)", len(panelPayload), len(nativePayload))
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	tlsConfig := &tls.Config{RootCAs: pool, ServerName: c.Domain, NextProtos: []string{"h2"}}
	start := func(username string) func() {
		var logs bytes.Buffer
		cmd := exec.Command(bin, vpn, hosts)
		cmd.Stdout, cmd.Stderr = &logs, &logs
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stop := sync.OnceFunc(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
		t.Cleanup(func() {
			stop()
			if t.Failed() {
				t.Log(logs.String())
			}
		})
		var dialErr error
		for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp4", tunnelAddr, tlsConfig)
			if err != nil {
				dialErr = err
				continue
			}
			protocol := conn.ConnectionState().NegotiatedProtocol
			conn.Close()
			if protocol != "h2" {
				t.Fatalf("ALPN %q, want h2", protocol)
			}
			stats, err := trustTunnelStatsAt(metricsAddr)
			if err != nil {
				dialErr = err
				continue
			}
			if len(stats) != 1 || stats[0].Username != username {
				t.Fatalf("unexpected /clients response: %+v", stats)
			}
			return stop
		}
		t.Fatalf("TrustTunnel startup: %v", dialErr)
		return nil
	}
	connect := func(password string) int {
		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   tlsConfig.Clone(),
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, tunnelAddr)
			},
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		req, err := http.NewRequest(http.MethodConnect, "https://"+c.address(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "127.0.0.1:65534"
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Name+":"+password)))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.ProtoMajor != 2 {
			t.Fatalf("got %s, want HTTP/2", response.Proto)
		}
		return response.StatusCode
	}
	stop := start(u.Name)
	password := trustTunnelPassword(u)
	if code := connect(password); code == http.StatusOK || code == http.StatusProxyAuthRequired {
		t.Fatalf("correct credentials and a private destination returned HTTP %d", code)
	}
	if code := connect("wrong-password"); code != http.StatusProxyAuthRequired {
		t.Fatalf("incorrect credentials returned HTTP %d", code)
	}
	stop()
	put("credentials.toml", closedTrustTunnelCredentials())
	defer start(trustTunnelClosedUser)()
	if code := connect(password); code != http.StatusProxyAuthRequired {
		t.Fatalf("revoked credentials returned HTTP %d", code)
	}
}
