// Package hostname validates DNS host names shared by setup and site scanning.
package hostname

import "strings"

// Valid reports whether h consists of valid DNS labels without a trailing dot.
func Valid(h string) bool {
	if len(h) > 253 || h == "" {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Domain reports whether h is a domain name: valid labels, at least two of
// them, and a last one that is not a number. That leaves out single-label
// names such as "localhost" and IPv4 literals such as "10.0.0.5".
func Domain(h string) bool {
	i := strings.LastIndexByte(h, '.')
	if i < 0 || !Valid(h) {
		return false
	}
	return strings.Trim(h[i+1:], "0123456789") != ""
}
