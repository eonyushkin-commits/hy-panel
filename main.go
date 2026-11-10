package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev" // set by -ldflags "-X main.version=v0.2.0"

const usage = `hy-panel — VPN-панель: Hysteria 2 и VLESS + Reality (Xray)

  hy-panel install     поставить панель или обновить программу (настройки и пользователи остаются);
                       протоколы ставятся и настраиваются в самой панели
  hy-panel info        адрес и пароль панели
  hy-panel passwd      новый пароль панели
  hy-panel uninstall -y          удалить панель; пользователи и настройки сохранятся
                       (-purge — удалить и их)

Их запускает агент панели (из окон «Протоколы»), можно и вручную, только с флагами:
  hy-panel settings -port … -obfs … -cert …   Hysteria: установить, сменить порт, обфускацию, сертификат
  hy-panel xray -target сайт [-port 443]       VLESS + Reality: установить или сменить сайт для маскировки
  hy-panel fetch hysteria|xray                 поставить или обновить сервер из официального релиза
`

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve()
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "settings":
		runSettings(os.Args[2:])
	case "fetch":
		runFetch(os.Args[2:])
	case "agent":
		runAgent()
	case "xray":
		runXray(os.Args[2:])
	case "info":
		printInfo(readEnv())
	case "passwd":
		runPasswd()
	case "version":
		fmt.Println(version)
	default:
		fmt.Print(usage)
	}
}

// serve runs the panel with the settings from /etc/hy-panel.env (systemd's
// EnvironmentFile). Only the loopback /auth listener is vital: if it cannot
// start the process exits; any other problem is shown in the panel instead.
func serve() {
	log.SetFlags(0) // journald adds timestamps
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	var workers sync.WaitGroup
	start := workers.Go
	env := readEnv()
	if len(env["HYP_PASSWORD"]) < 8 {
		log.Fatal("HYP_PASSWORD (8+ chars) is not set — run hy-panel install")
	}
	if err := checkEnv(env); err != nil {
		log.Fatal(err)
	}
	store, err := OpenStore(dataPath)
	if err != nil {
		log.Fatal(err)
	}
	var hyOpts *hyOpts
	// Hysteria is on once its config points at the panel; none or a fresh
	// template means it is not set up yet (the panel's Protocols section does it).
	cfgPath, _ := hyPaths(env)
	b, readErr := os.ReadFile(cfgPath)
	cfg, kind := classify(b, readErr)
	cfgErr, hyOn := "", kind == cfgPanel
	var warns []string
	switch {
	case kind == cfgOwnAuth:
		warns = append(warns, "Hysteria настроена не панелью и проверяет пароли сама: «Настроить» на карточке Hysteria перепишет её конфиг (прежний сохранится в .bak-hy-panel)")
	case kindErr(kind) != nil:
		// Keep /auth up, but hand out no links built from a config we could not read.
		log.Printf("WARN: %s: %v", cfgPath, kindErr(kind))
		cfgErr = "конфиг Hysteria: " + kindErr(kind).Error()
	case hyOn && cfg.TrafficStats.Listen == "":
		hyOn, cfgErr = false, "конфиг Hysteria: нет trafficStats — открой настройки Hysteria в панели"
	}
	if hyOn {
		checkHyConfig(cfg)
	}
	ep := endpointFor(cfg, env)
	if !hyOn {
		ep.Port = "" // no Hysteria links
	}
	// VLESS is on once hy-panel xray has set it up.
	var xs *xraySetup
	if xp := env["HYP_XRAY_CONFIG"]; xp != "" {
		if xs, err = readXray(xp); err != nil {
			log.Printf("WARN: xray %s: %v", xp, err)
			cfgErr = strings.TrimPrefix(cfgErr+"; конфиг Xray: "+err.Error(), "; ")
		} else {
			xs.Link.setServerVersion(xrayVersion())
			ep.Vless = &xs.Link
		}
	}
	// The session key survives restarts: the panel restarts after every
	// protocol change made in it, and must not log the admin out.
	key, err := sessionKey(dataDir + "/session.key")
	if err != nil {
		log.Printf("WARN: session key: %v", err)
		warns = append(warns, "Не удалось надёжно сохранить ключ сеансов: после перезапуска может потребоваться вход")
		if len(key) != 32 {
			key = make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				log.Fatal(err)
			}
		}
	}
	var stats *statsClient
	if hyOn {
		stats = statsFor(cfg)
		o := currentOpts(cfg)
		hyOpts = &o
	}
	app := newApp(store, stats, ep, env["HYP_PASSWORD"], key)
	app.sessionPath = dataDir + "/session.key"
	app.cfgErr, app.warns, app.hyOpts = cfgErr, warns, hyOpts
	app.agent = newAgentClient(agentSock)
	log.Printf("hy-panel %s; links: %s:%s sni=%q obfs=%q pinned=%v ech=%v", version,
		app.ep.Host, app.ep.Port, app.ep.SNI, app.ep.ObfsType, app.ep.Pin != "", app.ep.ECH != "")
	if xs != nil {
		app.addBackend(&xrayBackend{api: newXrayAPI(xs.API), tag: xs.Tag, flow: xs.Link.Flow})
		if xs.Warn != "" {
			log.Printf("WARN: xray: %s", xs.Warn)
			app.warns = append(app.warns, xs.Warn)
		}
		log.Printf("vless: :%s/tcp %s sni=%q, inbound %q, api %s", xs.Link.Port, xs.Link.Network, xs.Link.SNI, xs.Tag, xs.API)
		if xs.Link.Target != "" {
			start(func() { app.watchTarget(ctx, xs.Link.Target, xs.Link.SNI) })
		}
	}

	if sub := env["HYP_SUB_LISTEN"]; sub != "" {
		app.subBase = strings.TrimRight(env["HYP_SUB_URL"], "/")
		if _, p, err := net.SplitHostPort(sub); err == nil && app.subBase == "" {
			app.subBase = "http://" + net.JoinHostPort(app.ep.Host, p)
		}
		if strings.HasPrefix(app.subBase, "http://") {
			app.warns = append(app.warns, "Подписка идёт по открытому HTTP: пароли клиентов видны по пути. Поставь reverse-proxy с TLS и HYP_SUB_URL=https://…")
			log.Print("WARN: subscriptions over plain HTTP expose client passwords — put a TLS reverse proxy in front and set HYP_SUB_URL=https://…")
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /sub/{token}", app.handleSub)
		start(func() {
			app.keepServing(ctx, "подписка "+sub, func() error { return serveHTTP(ctx, server(sub, mux), false) })
		})
		log.Printf("subscriptions on %s (%s)", sub, app.subBase)
	}

	if port := env["HYP_UI_PORT"]; port != "" && port != "off" {
		addr := ":" + port
		start(func() {
			app.keepServing(ctx, "порт панели "+port, func() error {
				cert, fp, err := panelCert(dataDir, app.ep.Host)
				if err != nil {
					return err
				}
				srv := server(addr, underPath(env["HYP_UI_PATH"], app.routes(false)))
				srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
				log.Printf("UI on https://%s%s (cert sha256 %s)", addr, env["HYP_UI_PATH"], fp)
				return serveHTTP(ctx, srv, true)
			})
		})
	}
	start(func() { app.syncLoop(ctx, 10*time.Second) })
	log.Printf("auth backend on http://%s, users: %d", panelAddr, len(store.List()))
	err = serveHTTP(ctx, server(panelAddr, loopbackHost(app.routes(true))), false)
	cancel()
	workers.Wait()
	if saveErr := store.Flush(); saveErr != nil {
		log.Printf("save: %v", saveErr)
	}
	if err != nil && err != http.ErrServerClosed && err != context.Canceled {
		log.Fatal(err)
	}
}

// checkHyConfig warns about Hysteria settings that make the panel ineffective or exposed.
func checkHyConfig(c *hyConfig) {
	if c.Auth.Type != "http" {
		log.Printf("WARN: hysteria auth.type is %q — run hy-panel install", c.Auth.Type)
	} else if u, err := url.Parse(c.Auth.HTTP.URL); err != nil || u.Host != panelAddr || u.Path != "/auth" {
		log.Printf("WARN: hysteria auth.http.url is %q, expected %s", c.Auth.HTTP.URL, authURL)
	}
	if strings.HasPrefix(c.Listen, "realm") {
		log.Print("WARN: listen is a realm:// address: not supported, links would point nowhere")
	}
	if c.TLS.ClientCA != "" {
		log.Print("WARN: tls.clientCA (mTLS) is set: clients also need a client certificate, links alone will not connect")
	}
	if c.Mimic.Enabled {
		log.Print("WARN: mimic is enabled: clients must run Mimic too; links cannot carry it")
	}
	if h, _, _ := net.SplitHostPort(c.TrafficStats.Listen); h == "" || !isLoopbackHost(h) {
		log.Printf("WARN: trafficStats.listen %q is reachable from outside — use 127.0.0.1:<port>", c.TrafficStats.Listen)
	}
}

// sessionKey reads the key that signs panel sessions, creating it once.
func sessionKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid session key length")
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, writeAtomic(path, key, 0o600)
}
