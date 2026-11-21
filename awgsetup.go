package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/transaction"
)

// Source pins from official Amnezia repositories, not a third-party installer.
const awgModuleTag = "v3.1.20260906"
const awgModuleCommit = "4569c4c67f3a57414969260cafbbd04694fbaae0"
const awgToolsTag = "v3.1.20260812"
const awgToolsCommit = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"

func installAWGKernel() error {
	if runtime.GOOS != "linux" {
		return errors.New("AmneziaWG требует Linux")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return errors.New("ядерный AmneziaWG устанавливается на VPS, не внутри Docker")
	}
	_, moduleErr := awgExec("", "modprobe", "amneziawg")
	_, toolsErr := exec.LookPath("awg")
	missingNetworkTool := false
	for _, name := range []string{"ip", "nft", "iptables"} {
		if _, err := exec.LookPath(name); err != nil {
			missingNetworkTool = true
		}
	}
	if moduleErr == nil && toolsErr == nil && !missingNetworkTool {
		return nil
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return errors.New("автоустановка AWG поддерживает Debian/Ubuntu; установи модуль amneziawg и утилиты awg, ip, nft, iptables")
	}
	run := func(dir, name string, args ...string) error {
		fmt.Printf("→ %s %s\n", name, strings.Join(args, " "))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.WaitDelay = 5 * time.Second
		return cmd.Run()
	}
	if err := run("", "apt-get", "update"); err != nil {
		return err
	}
	packages := []string{"install", "-y", "iproute2", "nftables", "iptables"}
	if moduleErr != nil || toolsErr != nil {
		packages = append(packages, "git", "build-essential", "pkg-config", "libmnl-dev")
	}
	if moduleErr != nil {
		kernel, err := awgExec("", "uname", "-r")
		if err != nil {
			return err
		}
		packages = append(packages, "dkms", "linux-headers-"+strings.TrimSpace(string(kernel)))
		if version, _ := os.ReadFile("/proc/version"); strings.Contains(strings.ToLower(string(version)), "clang") {
			packages = append(packages, "clang", "lld", "llvm")
		}
	}
	if err := run("", "apt-get", packages...); err != nil {
		return fmt.Errorf("зависимости AWG (нужны headers текущего ядра): %w", err)
	}
	if err := os.MkdirAll("/usr/local/src", 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/usr/local/src", "hy-panel-awg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	clone := func(repo, tag, commit, dest string) error {
		if err := run("", "git", "clone", "--depth", "1", "--branch", tag, "https://github.com/amnezia-vpn/"+repo+".git", dest); err != nil {
			return err
		}
		out, err := awgExec("", "git", "-C", dest, "rev-parse", "HEAD")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(out)) != commit {
			return errors.New("AWG: тег не совпал с закреплённым commit; сборка отменена")
		}
		return nil
	}
	if moduleErr != nil {
		source := filepath.Join(dir, "module")
		if err := clone("amneziawg-linux-kernel-module", awgModuleTag, awgModuleCommit, source); err != nil {
			return err
		}
		// A panel-specific DKMS version avoids overwriting another installer's
		// /usr/src/amneziawg-1.0.0 tree. DKMS handles future kernel rebuilds.
		version := "hyp-3.1.20260906"
		dkmsDir := "/usr/src/amneziawg-" + version
		if _, err := os.Stat(dkmsDir); errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(dkmsDir, 0755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dkmsDir, ".hy-panel-source"), []byte(awgModuleCommit), 0644); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			marker, err := os.ReadFile(filepath.Join(dkmsDir, ".hy-panel-source"))
			if err != nil || strings.TrimSpace(string(marker)) != awgModuleCommit {
				return errors.New("каталог DKMS занят чужой установкой; ничего не заменено")
			}
		}
		// Resume an interrupted source preparation only in our marked tree.
		{
			if err := run(filepath.Join(source, "src"), "make", "dkms-install", "DKMSDIR="+dkmsDir); err != nil {
				return err
			}
			conf := filepath.Join(dkmsDir, "dkms.conf")
			data, err := os.ReadFile(conf)
			if err != nil {
				return err
			}
			data = []byte(strings.Replace(string(data), `PACKAGE_VERSION="1.0.0"`, `PACKAGE_VERSION="`+version+`"`, 1))
			if err := os.WriteFile(conf, data, 0644); err != nil {
				return err
			}
		}
		registered, err := awgExec("", "dkms", "status", "-m", "amneziawg", "-v", version)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(registered)) == "" {
			if err := run("", "dkms", "add", "-m", "amneziawg", "-v", version); err != nil {
				return err
			}
		}
		for _, action := range []string{"build", "install"} {
			if err := run("", "dkms", action, "-m", "amneziawg", "-v", version); err != nil {
				return err
			}
		}
		if _, err := awgExec("", "modprobe", "amneziawg"); err != nil {
			return fmt.Errorf("модуль AWG не загрузился; проверь headers и подпись Secure Boot: %w", err)
		}
	}
	if toolsErr != nil {
		source := filepath.Join(dir, "tools")
		if err := clone("amneziawg-tools", awgToolsTag, awgToolsCommit, source); err != nil {
			return err
		}
		if err := run(filepath.Join(source, "src"), "make"); err != nil {
			return err
		}
		// Install only the binary used by the agent; no wg-quick hooks/units.
		data, err := os.ReadFile(filepath.Join(source, "src", "wg"))
		if err != nil {
			return err
		}
		if err := writeAtomic("/usr/local/bin/awg", data, 0755); err != nil {
			return err
		}
	}
	return nil
}

func runAWG(args []string) {
	fs := flag.NewFlagSet("awg", flag.ExitOnError)
	port := fs.String("port", "", "UDP port (new: 51820)")
	subnet := fs.String("subnet", "", "private /16 subnet (new: 10.77.0.0/16)")
	dns := fs.String("dns", "", "public IPv4 DNS, comma separated")
	mtu := fs.Int("mtu", 0, "MTU 1280..1380")
	obfuscationFile := fs.String("obfuscation-file", "", "AWG 3.1 JSON file (omitted: preserve current)")
	obfuscationStdin := fs.Bool("obfuscation-stdin", false, "read AWG 3.1 JSON from stdin")
	fs.Parse(args)
	needRoot("awg")
	env := readEnv()
	if !installed(env) {
		log.Fatal("сначала hy-panel install")
	}
	step("panel settings", checkEnv(env))
	path := env["HYP_AWG_CONFIG"]
	if path == "" {
		path = awgConfigPath
	}
	c := freshAWG()
	old, err := readAWG(path)
	if err == nil {
		c = old
	} else if !errors.Is(err, os.ErrNotExist) {
		step("read AWG config", err)
	}
	next := *c
	c = &next
	if *port != "" {
		c.Port = *port
	}
	if *subnet != "" {
		c.Subnet = *subnet
	}
	if *dns != "" {
		c.DNS = *dns
	}
	if *mtu != 0 {
		c.MTU = *mtu
	}
	if *obfuscationFile != "" && *obfuscationStdin {
		log.Fatal("выбери один источник параметров AWG")
	}
	if *obfuscationFile != "" || *obfuscationStdin {
		var data []byte
		if *obfuscationStdin {
			data, err = io.ReadAll(io.LimitReader(os.Stdin, 16385))
		} else {
			data, err = os.ReadFile(*obfuscationFile)
		}
		step("read AWG 3.1 options", err)
		step("AWG 3.1 options", parseAWGObfuscation(string(data), &c.awgObfuscation))
	}
	step("AWG settings", c.check())
	if old == nil || old.Port != c.Port {
		conn, err := net.ListenPacket("udp", ":"+c.Port)
		step("UDP port "+c.Port, err)
		conn.Close()
	}
	step("AmneziaWG kernel and tools", installAWGKernel())
	_, err = awgNetwork(c)
	step("AWG subnet and network", err)
	step("AWG config directory", os.MkdirAll(filepath.Dir(path), 0700))
	data, _ := json.MarshalIndent(c, "", "  ")
	env["HYP_AWG_CONFIG"] = path
	apply := func() error {
		code, out, err := newAgentClient(agentSock).do("POST", "/awg/reconfigure", nil)
		if err != nil {
			return err
		}
		if code != 200 {
			return errors.New(strings.TrimSpace(string(out)))
		}
		if err := restartService("hy-panel"); err != nil {
			return err
		}
		return waitPanelReady()
	}
	ufwAllow(c.Port + "/udp")
	noInterrupt()
	step("AWG settings (rollback on failure)", transaction.Run([]transaction.File{
		{Path: path, Data: append(data, '\n'), Options: atomicfile.Options{Mode: 0600}},
		{Path: envPath, Data: renderEnv(env), Options: atomicfile.Options{Mode: 0600}},
	}, apply, apply))
	fmt.Printf("Готово: AmneziaWG, UDP %s, %s, MTU %d. Скачай .conf пользователя в панели. IPv4 работает через туннель, IPv6 внутри туннеля блокируется.\n", c.Port, c.Subnet, c.MTU)
}

func awgStatus() protoStatus {
	s := protoStatus{}
	for _, name := range []string{"awg", "ip", "nft", "iptables"} {
		if _, err := exec.LookPath(name); err != nil {
			s.LatestErr = "Не найдена утилита " + name
			return s
		}
	}
	if _, err := awgExec("", "modinfo", "amneziawg"); err != nil {
		s.LatestErr = "Модуль ядра AmneziaWG не установлен"
		return s
	}
	s.Installed = true
	if out, err := awgExec("", "awg", "--version"); err == nil {
		s.Version = strings.TrimSpace(string(out))
	}
	if c, err := configuredAWG(); err == nil {
		s.Active, _ = awgOwned(c)
	}
	return s
}

// Invoked by systemd even after an abnormal agent exit. Only the owned
// interface is removed; host forwarding and foreign firewall rules stay.
func runAWGDown() {
	needRoot("awg-down")
	c, err := configuredAWG()
	if err != nil {
		return
	}
	var state awgRuntimeState
	b, err := os.ReadFile(agentDir + "/awg-state.json")
	if err == nil && json.Unmarshal(b, &state) == nil && state.Alias == awgAlias(c) && validExternalInterface(state.External) {
		c.Subnet = state.Subnet
		step("AWG saved state", c.check())
		m := &awgRuntime{config: c, external: state.External}
		step("stop AWG", m.down())
	} else {
		owned, err := awgOwned(c)
		step("AWG ownership", err)
		if owned {
			_, err = awgExec("", "ip", "link", "del", "dev", awgInterface)
			step("stop AWG", err)
		}
	}
}
