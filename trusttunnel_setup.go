package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/hostname"
	"github.com/eonyushkin-commits/hy-panel/internal/transaction"
)

const (
	trustTunnelVersion = "v1.3.1"
	trustTunnelService = "hy-panel-trusttunnel"
	trustTunnelBin     = "/usr/local/bin/" + trustTunnelService
	trustTunnelUnit    = "/etc/systemd/system/" + trustTunnelService + ".service"
	trustTunnelDir     = "/etc/hy-panel-trusttunnel"
	trustTunnelMeta    = trustTunnelDir + "/panel.json"
	trustTunnelKey     = trustTunnelDir + "/key.pem"
	trustTunnelCert    = trustTunnelDir + "/cert.pem"
	trustTunnelCreds   = trustTunnelDir + "/credentials.toml"
	trustTunnelVPN     = trustTunnelDir + "/vpn.toml"
	trustTunnelHosts   = trustTunnelDir + "/hosts.toml"
	trustTunnelMetrics = "127.0.0.1:10087"
	trustTunnelPort    = "9444"
)

const trustTunnelUnitText = `[Unit]
Description=hy-panel TrustTunnel endpoint
Wants=network-online.target
After=network-online.target

[Service]
User=` + trustTunnelService + `
Group=` + trustTunnelService + `
ExecStart=` + trustTunnelBin + " " + trustTunnelVPN + " " + trustTunnelHosts + `
Restart=on-failure
RestartSec=2
TimeoutStopSec=5
LimitNOFILE=65536
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
`

func trustTunnelSettings(domain, port string) (trustTunnelConfig, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !hostname.Domain(domain) {
		return trustTunnelConfig{}, errors.New("TrustTunnel: укажи DNS-имя сервера")
	}
	if port == "" {
		port = trustTunnelPort
	}
	if !validPortNumber(port) {
		return trustTunnelConfig{}, errors.New("TrustTunnel: нужен порт TCP 1–65535")
	}
	n, _ := strconv.Atoi(port)
	if n == 10087 {
		return trustTunnelConfig{}, errors.New("TCP 10087 зарезервирован для локальной статистики TrustTunnel")
	}
	return trustTunnelConfig{Domain: domain, Port: strconv.Itoa(n)}, nil
}

func readTrustTunnel() (*trustTunnelConfig, error) {
	b, err := os.ReadFile(trustTunnelMeta)
	if err != nil {
		return nil, err
	}
	var c trustTunnelConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	c, err = trustTunnelSettings(c.Domain, c.Port)
	if err != nil {
		return nil, err
	}
	b, err = os.ReadFile(trustTunnelCert)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("некорректный сертификат TrustTunnel")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := cert.VerifyHostname(c.Domain); err != nil {
		return nil, err
	}
	c.cert = cert.Raw
	return &c, nil
}

func trustTunnelCertificate(domain string) (cert, key []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, DNSNames: []string{domain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), nil
}

func trustTunnelVPNConfig(port, credentials, metrics string) []byte {
	// Endpoint v1.3.1 also uses the HTTP/1 codec for its metrics listener.
	return fmt.Appendf(nil, `listen_address = "0.0.0.0:%s"
ipv6_available = false
allow_private_network_connections = false
credentials_file = %q

[listen_protocols.http1]

[listen_protocols.http2]

[metrics]
address = %q
request_timeout_secs = 3
per_client_metrics = true
`, port, credentials, metrics)
}

func trustTunnelHostsConfig(domain, cert, key string) []byte {
	return fmt.Appendf(nil, `[[main_hosts]]
hostname = %q
cert_chain_path = %q
private_key_path = %q
`, domain, cert, key)
}

func installTrustTunnelBinary() error {
	if fileExists(trustTunnelBin) {
		return nil
	}
	var arch, digest string
	switch runtime.GOARCH {
	case "amd64":
		arch, digest = "x86_64", "29fd330eafab37eb8ab668dcbd57aa8f99b46e26b268e5dc9b416a483fadca97"
	case "arm64":
		arch, digest = "aarch64", "b82795893d50ea1ffe92fe5712d14282a024e87ee968cca25afdc4cb0aae6238"
	default:
		return fmt.Errorf("TrustTunnel: архитектура %s не поддерживается", runtime.GOARCH)
	}
	base := "https://github.com/TrustTunnel/TrustTunnel/releases/download/" + trustTunnelVersion + "/"
	name := "trusttunnel-" + trustTunnelVersion + "-linux-" + arch + ".tar.gz"
	b, err := download(base, name, func(string) (string, error) { return digest, nil })
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return fmt.Errorf("TrustTunnel: trusttunnel_endpoint в архиве: %w", err)
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == "trusttunnel_endpoint" {
			if h.Size <= 0 || h.Size > 100<<20 {
				return errors.New("TrustTunnel: некорректный размер trusttunnel_endpoint")
			}
			bin, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			return atomicfile.Replace(trustTunnelBin, bin, atomicfile.Options{Mode: 0755})
		}
	}
}

func trustTunnelStatus() protoStatus {
	installed := fileExists(trustTunnelBin) && fileExists(trustTunnelUnit)
	s := protoStatus{Installed: installed}
	if installed {
		s.Version = trustTunnelVersion
		s.Active = systemctl("is-active", "--quiet", trustTunnelService) == nil
	}
	return s
}

func runTrustTunnel(args []string) {
	fs := flag.NewFlagSet(protoTrustTunnel, flag.ExitOnError)
	domain := fs.String("domain", "", "DNS hostname of this VPS")
	port := fs.String("port", trustTunnelPort, "TCP port")
	stop := fs.Bool("stop", false, "disable TrustTunnel")
	fs.Parse(args)
	needRoot(protoTrustTunnel)
	env := readEnv()
	if !installed(env) {
		log.Fatal("сначала hy-panel install")
	}
	step("panel settings", checkEnv(env))
	if *stop {
		step("отключение TrustTunnel", stopTrustTunnel(env))
		return
	}
	c, err := trustTunnelSettings(*domain, *port)
	step("настройки TrustTunnel", err)
	step("каталог TrustTunnel", os.MkdirAll(trustTunnelDir, 0750))
	step("настройка TrustTunnel", configureTrustTunnel(c, env))
	fmt.Printf("TrustTunnel готов: %s, HTTP/2. Ссылка и QR-код доступны у пользователя.\n", c.address())
}

func trustTunnelFileOptions() atomicfile.Options {
	_, gid := userIDs(trustTunnelService)
	return atomicfile.Options{Mode: 0640, Owner: &atomicfile.Owner{UID: 0, GID: gid}}
}

func configureTrustTunnel(c trustTunnelConfig, env map[string]string) error {
	lock, err := lockTrustTunnel()
	if err != nil {
		return err
	}
	defer lock.Close()
	old, _ := readTrustTunnel()
	wasActive := systemctl("is-active", "--quiet", trustTunnelService) == nil
	wasEnabled := systemctl("is-enabled", "--quiet", trustTunnelService) == nil
	checkPort := func(address string) error {
		l, err := net.Listen("tcp4", address)
		if err != nil {
			return fmt.Errorf("TrustTunnel: TCP %s: %w", address, err)
		}
		return l.Close()
	}
	if !wasActive || old == nil || old.Port != c.Port {
		if err := checkPort("0.0.0.0:" + c.Port); err != nil {
			return err
		}
	}
	if !wasActive {
		if err := checkPort(trustTunnelMetrics); err != nil {
			return err
		}
	}
	if err := installTrustTunnelBinary(); err != nil {
		return err
	}
	if err := systemUser(trustTunnelService, ""); err != nil {
		return err
	}
	opts := trustTunnelFileOptions()
	if err := os.Chown(trustTunnelDir, 0, opts.Owner.GID); err != nil {
		return err
	}
	data, _ := json.Marshal(c)
	env["HYP_TRUSTTUNNEL"] = "1"
	files := []transaction.File{
		{Path: trustTunnelVPN, Data: trustTunnelVPNConfig(c.Port, trustTunnelCreds, trustTunnelMetrics), Options: opts},
		{Path: trustTunnelHosts, Data: trustTunnelHostsConfig(c.Domain, trustTunnelCert, trustTunnelKey), Options: opts},
		{Path: trustTunnelMeta, Data: data},
		{Path: trustTunnelUnit, Data: []byte(trustTunnelUnitText), Options: atomicfile.Options{Mode: 0644}},
		{Path: envPath, Data: renderEnv(env)},
	}
	cert, err := os.ReadFile(trustTunnelCert)
	renew := old == nil || old.Domain != c.Domain || !fileExists(trustTunnelKey)
	if !renew {
		previous, parseErr := x509.ParseCertificate(old.cert)
		renew = parseErr != nil || time.Until(previous.NotAfter) < 30*24*time.Hour
	}
	if err != nil || renew {
		var key []byte
		cert, key, err = trustTunnelCertificate(c.Domain)
		if err != nil {
			return err
		}
		files = append(files, transaction.File{Path: trustTunnelCert, Data: cert, Options: opts},
			transaction.File{Path: trustTunnelKey, Data: key, Options: opts})
	}
	if !fileExists(trustTunnelCreds) {
		files = append(files, transaction.File{Path: trustTunnelCreds, Data: closedTrustTunnelCredentials(), Options: opts})
	}
	ufwAllow(c.Port + "/tcp")
	noInterrupt()
	return transaction.Run(files, func() error {
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
		if err := systemctl("enable", trustTunnelService); err != nil {
			return err
		}
		if err := restartService(trustTunnelService); err != nil {
			return err
		}
		if err := waitTrustTunnel(c, cert); err != nil {
			return err
		}
		return reloadTrustTunnelPanel()
	}, func() error {
		var unitErr error
		if wasActive {
			unitErr = errors.Join(systemctl("daemon-reload"), restartService(trustTunnelService))
		} else {
			unitErr = systemctl("stop", trustTunnelService)
		}
		if !wasEnabled {
			// The unit file may have been removed by rollback, so also remove
			// the fixed enable symlink when systemctl can no longer find it.
			err := os.Remove("/etc/systemd/system/multi-user.target.wants/" + trustTunnelService + ".service")
			if !errors.Is(err, os.ErrNotExist) {
				unitErr = errors.Join(unitErr, err)
			}
		}
		return errors.Join(unitErr, systemctl("daemon-reload"), reloadTrustTunnelPanel())
	})
}

func waitTrustTunnel(c trustTunnelConfig, cert []byte) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return errors.New("TrustTunnel: не удалось загрузить сертификат")
	}
	opts := &tls.Config{ServerName: c.Domain, RootCAs: pool, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}
	var err error
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(150 * time.Millisecond) {
		var conn *tls.Conn
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp4", "127.0.0.1:"+c.Port, opts)
		if err == nil {
			alpn := conn.ConnectionState().NegotiatedProtocol
			conn.Close()
			if alpn == "h2" {
				_, err = readTrustTunnelStats()
				if err == nil {
					return nil
				}
			} else {
				err = fmt.Errorf("ожидался HTTP/2, получен ALPN %q", alpn)
			}
		}
	}
	return fmt.Errorf("TrustTunnel: служба не готова, проверь journalctl -u %s: %w", trustTunnelService, err)
}

func reloadTrustTunnelPanel() error {
	if err := restartService("hy-panel"); err != nil {
		return err
	}
	return waitPanelReady()
}

func stopTrustTunnel(env map[string]string) error {
	if env["HYP_TRUSTTUNNEL"] != "1" {
		return nil
	}
	lock, err := lockTrustTunnel()
	if err != nil {
		return err
	}
	defer lock.Close()
	wasActive := systemctl("is-active", "--quiet", trustTunnelService) == nil
	wasEnabled := systemctl("is-enabled", "--quiet", trustTunnelService) == nil
	delete(env, "HYP_TRUSTTUNNEL")
	noInterrupt()
	return transaction.Run([]transaction.File{
		{Path: trustTunnelCreds, Data: closedTrustTunnelCredentials(), Options: trustTunnelFileOptions()},
		{Path: envPath, Data: renderEnv(env)},
	}, func() error {
		if err := systemctl("disable", "--now", trustTunnelService); err != nil {
			return err
		}
		return reloadTrustTunnelPanel()
	}, func() error {
		var err error
		if wasEnabled {
			err = systemctl("enable", trustTunnelService)
		}
		return errors.Join(err, restoreServiceState(trustTunnelService, wasActive), reloadTrustTunnelPanel())
	})
}
