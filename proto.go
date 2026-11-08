package main

import "fmt"

const protoHy2 = "hysteria2"

// Keep protocol IDs in the API and existing client URLs stable.
func (e Endpoint) running() []hy2Proto {
	if e.Port == "" {
		return nil
	}
	return []hy2Proto{{}}
}
func (e Endpoint) userProtos(User) []hy2Proto { return e.running() }
func (e Endpoint) Protocols() []string {
	if e.Port == "" {
		return nil
	}
	return []string{protoHy2}
}
func (e Endpoint) UserProtocols(User) []string { return e.Protocols() }
func (e Endpoint) Link(id string, u User) string {
	if id == protoHy2 && e.Port != "" {
		return e.URI(u)
	}
	return ""
}
func (e Endpoint) URIs(u User) []string {
	if e.Port == "" {
		return nil
	}
	return []string{e.URI(u)}
}
func (e Endpoint) MihomoProxy(id string, u User) string {
	if id == protoHy2 && e.Port != "" {
		return e.Mihomo(u)
	}
	return ""
}
func (e Endpoint) MihomoDoc(u User) string { return "proxies:\n" + e.MihomoProxy(protoHy2, u) }

// Retain the old fallback export URL for existing integrations.
func (e Endpoint) MihomoFallback(u User) string {
	proxies := ""
	if e.Port != "" {
		proxies = fmt.Sprintf("%q", e.remark(u))
	}
	return e.MihomoDoc(u) + fmt.Sprintf("proxy-groups:\n  - name: %q\n    type: fallback\n    proxies: [%s]\n    url: https://www.gstatic.com/generate_204\n    interval: 120\n", e.groupName(), proxies)
}
func (e Endpoint) groupName() string {
	if e.Name == "" {
		return "VPN"
	}
	return e.Name
}
