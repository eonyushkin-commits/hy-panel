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

const usage = `hy-panel — пользователи для Hysteria 2

  hy-panel install     установить или обновить (повторный запуск ничего не меняет, кроме программы)
  hy-panel settings    поменять порт, обфускацию или сертификат Hysteria
  hy-panel info        адрес и пароль панели
  hy-panel passwd      новый пароль панели
  hy-panel uninstall   удалить панель; пользователи и настройки сохранятся
                       (-purge — удалить и их)
  hy-panel serve       запуск панели (его делает systemd)
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
		runSettings()
	case "info":
		printInfo()
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
	env := map[string]string{}
	for _, k := range envKeys {
		env[k] = os.Getenv(k)
	}
	if len(env["HYP_PASSWORD"]) < 8 {
		log.Fatal("HYP_PASSWORD (8+ chars) is not set — run hy-panel install")
	}
	store, err := OpenStore(dataPath)
	if err != nil {
		log.Fatal(err)
	}
	cfgPath := envOr(env, "HYP_HY_CONFIG", defaultCfg)
	cfg, err := loadHyConfig(cfgPath)
	if err == nil && cfg.TrafficStats.Listen == "" {
		err = fmt.Errorf("%s: no trafficStats — run hy-panel install", cfgPath)
	}
	cfgErr := ""
	if err != nil {
		// Keep /auth up, but hand out no links built from a config we could not read.
		log.Printf("WARN: %v", err)
		cfgErr = "конфиг Hysteria: " + err.Error()
		cfg = &hyConfig{}
	}
	checkHyConfig(cfg)
	key := make([]byte, 32)
	rand.Read(key)
	app := newApp(store, newStatsClient(cfg.TrafficStats.Listen, cfg.TrafficStats.Secret), endpointFor(cfg, env), env["HYP_PASSWORD"], key)
	app.cfgErr = cfgErr
	log.Printf("hy-panel %s; links: %s:%s sni=%q obfs=%q pinned=%v ech=%v", version,
		app.ep.Host, app.ep.Port, app.ep.SNI, app.ep.ObfsType, app.ep.Pin != "", app.ep.ECH != "")

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
	log.Fatal(server(panelAddr, app.routes(true)).ListenAndServe())
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
