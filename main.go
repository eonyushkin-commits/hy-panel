package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev" // set by -ldflags "-X main.version=v0.2.0"

const usage = `hy-panel — пользователи для Hysteria 2 и VLESS + Reality (Xray)

  hy-panel install     установить или обновить (повторный запуск ничего не меняет, кроме программы)
  hy-panel settings    поменять порт, обфускацию или сертификат Hysteria
  hy-panel xray        добавить VLESS + Reality (Xray) или сменить его сайт для маскировки
  hy-panel awg         добавить AmneziaWG 3.1 или сменить его порт
  hy-panel info        адрес и пароль панели
  hy-panel passwd      новый пароль панели
  hy-panel uninstall   удалить панель; пользователи и настройки сохранятся
                       (-purge — удалить и их)
  hy-panel fetch hysteria|xray   поставить или обновить сервер протокола из официального релиза
  hy-panel serve       запуск панели (его делает systemd)
  hy-panel agent       root-помощник панели (его делает systemd)
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
	case "awg":
		runAWG(os.Args[2:])
	case "awg-serve":
		runAWGServe()
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
		warns = append(warns, "Hysteria работает со своими паролями, не через панель: подключи её командой hy-panel install")
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
			ep.Vless = &xs.Link
		}
	}
	// The session key survives restarts: the panel restarts after every
	// protocol change made in it, and must not log the admin out.
	key, err := sessionKey(dataDir + "/session.key")
	if err != nil {
		log.Printf("WARN: session key: %v", err)
		key = make([]byte, 32)
		rand.Read(key)
	}
	var stats *statsClient
	if hyOn {
		stats = newStatsClient(cfg.TrafficStats.Listen, cfg.TrafficStats.Secret)
		o := currentOpts(cfg)
		hyOpts = &o
	}
	app := newApp(store, stats, ep, env["HYP_PASSWORD"], key)
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
			go app.watchTarget(xs.Link.Target, xs.Link.SNI)
		}
	}
	if fileExists(awgCfgPath) {
		if c, err := readAWG(awgCfgPath); err != nil {
			log.Printf("WARN: %s: %v", awgCfgPath, err)
			app.cfgErr = strings.TrimPrefix(app.cfgErr+"; конфиг AmneziaWG: "+err.Error(), "; ")
		} else {
			app.ep.AWG = c
			app.addBackend(newAWGBackend(newAWGClient(awgSock)))
			log.Printf("awg: udp :%d", c.Port)
		}
	}

	if port := env["HYP_UI_PORT"]; port != "" && port != "off" {
		addr := ":" + port
		go app.keepServing("порт панели "+port, func() error {
			cert, fp, err := panelCert(dataDir, app.ep.Host)
			if err != nil {
				return err
			}
			srv := server(addr, underPath(env["HYP_UI_PATH"], app.routes(false)))
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			log.Printf("UI on https://%s%s (cert sha256 %s)", addr, env["HYP_UI_PATH"], fp)
			return srv.ListenAndServeTLS("", "")
		})
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
		go app.keepServing("подписка "+sub, server(sub, mux).ListenAndServe)
		log.Printf("subscriptions on %s (%s)", sub, app.subBase)
	}

	// On stop, write the traffic counted since the last flush.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		if err := store.Flush(); err != nil {
			log.Printf("save: %v", err)
		}
		os.Exit(0)
	}()

	go app.syncLoop(10 * time.Second)
	log.Printf("auth backend on http://%s, users: %d", panelAddr, len(store.List()))
	log.Fatal(server(panelAddr, loopbackHost(app.routes(true))).ListenAndServe())
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
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	rand.Read(key)
	return key, writeAtomic(path, key, 0o600)
}
