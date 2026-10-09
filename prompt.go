package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// prompter asks questions on the terminal, like 3x-ui's installer. Without a
// terminal (piped, CI) every question returns its default.
type prompter struct{ in *bufio.Reader }

func newPrompter() *prompter {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return &prompter{}
	}
	return &prompter{in: bufio.NewReader(tty)}
}

func (p *prompter) line(q, def string) string {
	if p.in == nil {
		return def
	}
	fmt.Print(q)
	l, err := p.in.ReadString('\n')
	if err != nil && l == "" {
		fmt.Println()
		p.in = nil // Ctrl-D: the rest of the questions take their defaults
	}
	if l = strings.TrimSpace(l); l == "" {
		return def
	}
	return l
}

// choose shows numbered options and returns the picked index; Enter = def.
func (p *prompter) choose(title string, opts []string, def int) int {
	if p.in == nil {
		return def
	}
	fmt.Println("\n" + title)
	for i, o := range opts {
		mark := ""
		if i == def {
			mark = "  ← по умолчанию"
		}
		fmt.Printf("  %d) %s%s\n", i+1, o, mark)
	}
	for {
		a := p.line(fmt.Sprintf("Выбор [%d]: ", def+1), "")
		if a == "" {
			return def
		}
		if n, err := strconv.Atoi(a); err == nil && n >= 1 && n <= len(opts) {
			return n - 1
		}
		fmt.Printf("  введи номер от 1 до %d\n", len(opts))
	}
}

func (p *prompter) yes(q string, def bool) bool {
	d, hint := "n", "y/N"
	if def {
		d, hint = "y", "Y/n"
	}
	a := strings.ToLower(p.line(q+" ["+hint+"]: ", d))
	return strings.HasPrefix(a, "y") || strings.HasPrefix(a, "д")
}

// need asks until the answer is non-empty; closed input aborts.
func (p *prompter) need(q string) string {
	for {
		if a := p.line(q, ""); a != "" {
			return a
		}
		if p.in == nil {
			log.Fatal("✗ ввод прерван")
		}
	}
}

// port asks for a TCP/UDP port number.
func (p *prompter) port(q string) string {
	for {
		a := p.need(q)
		if n, err := strconv.Atoi(a); err == nil && n > 0 && n < 65536 {
			return a
		}
		fmt.Println("  порт — число от 1 до 65535")
	}
}
