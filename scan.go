package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Finding a site for Reality: what the guide did by hand, RealiTLScanner
// over the server's /24 and then a check of each candidate. A good site is
// a neighbour (same /24, so its IP does not stand out next to ours), speaks
// TLS 1.3 with X25519 and HTTP/2, has a valid certificate and answers 200.

type siteCandidate struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`     // where it answered
	SameIP bool   `json:"sameIP"` // its DNS points at that very address
	Ms     int    `json:"ms"`     // time to the first response
	Status int    `json:"status"` // GET / (redirects are not followed)
}

// siteScanner holds what tests replace: the port, DNS and trusted roots.
type siteScanner struct {
	port    string
	resolve func(ctx context.Context, host string) ([]net.IP, error)
	roots   *x509.CertPool // nil: the system's
	timeout time.Duration
}

func newSiteScanner() *siteScanner {
	return &siteScanner{port: "443", timeout: 4 * time.Second, resolve: func(ctx context.Context, h string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip4", h)
	}}
}

func browserTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2"}}
}

// probe connects to an address the way RealiTLScanner does and returns the
// names on its certificate if it speaks TLS 1.3 + h2.
func (s *siteScanner) probe(ctx context.Context, ip net.IP) []string {
	d := &net.Dialer{Timeout: s.timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), s.port))
	if err != nil {
		return nil
	}
	defer c.Close()
	cfg := browserTLS()
	cfg.InsecureSkipVerify = true // the name is what we are after
	tc := tls.Client(c, cfg)
	tc.SetDeadline(time.Now().Add(s.timeout))
	if tc.HandshakeContext(ctx) != nil {
		return nil
	}
	st := tc.ConnectionState()
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" || len(st.PeerCertificates) == 0 {
		return nil
	}
	leaf := st.PeerCertificates[0]
	var names []string
	for _, n := range append(slices.Clone(leaf.DNSNames), leaf.Subject.CommonName) {
		n = strings.TrimPrefix(strings.ToLower(n), "*.")
		if strings.Contains(n, ".") && validHostname(n) && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// verify checks a domain the way a browser and a probe see it: through its
// own DNS, with certificate verification, TLS 1.3 + X25519 + h2, GET /.
func (s *siteScanner) verify(ctx context.Context, domain string, found net.IP, net24 *net.IPNet) (siteCandidate, bool) {
	c := siteCandidate{Domain: domain, IP: found.String()}
	ips, err := s.resolve(ctx, domain)
	if err != nil {
		return c, false
	}
	var to net.IP
	for _, ip := range ips {
		if ip.Equal(found) {
			c.SameIP, to = true, ip
			break
		}
		if net24.Contains(ip) && to == nil {
			to = ip
		}
	}
	if to == nil {
		return c, false // lives elsewhere (a CDN): not a neighbour
	}
	cfg := browserTLS()
	cfg.ServerName, cfg.RootCAs = domain, s.roots
	tr := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   cfg,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: s.timeout}).DialContext(ctx, n, net.JoinHostPort(to.String(), s.port))
		},
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 2 * s.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36")
	resp, err := hc.Do(req)
	if err != nil {
		return c, false
	}
	resp.Body.Close()
	c.Ms, c.Status = int(time.Since(start)/time.Millisecond), resp.StatusCode
	ok := resp.ProtoMajor == 2 && resp.TLS != nil && resp.TLS.Version == tls.VersionTLS13
	return c, ok
}

// scanResult is a search's progress and finds, as the panel shows them.
type scanResult struct {
	Running bool            `json:"running"`
	Net     string          `json:"net"`
	Done    int             `json:"done"`
	Total   int             `json:"total"`
	Found   []siteCandidate `json:"found"`
}

// scanState is the panel's one running (or last) search.
type scanState struct {
	mu sync.Mutex
	scanResult
}

func (st *scanState) snapshot() scanResult {
	st.mu.Lock()
	defer st.mu.Unlock()
	r := st.scanResult
	r.Found = append([]siteCandidate{}, st.Found...)
	return r
}

// run scans the /24 of server: every neighbour is probed, every name found
// is verified; good ones (200 first, then same IP, then fast) end up in Found.
func (s *siteScanner) run(st *scanState, server net.IP) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ip4 := server.To4()
	net24 := &net.IPNet{IP: ip4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
	st.mu.Lock()
	st.Net, st.Total = net24.String(), 254
	st.mu.Unlock()

	type hit struct {
		ip    net.IP
		names []string
	}
	ips := make(chan net.IP)
	hits := make(chan hit)
	var wg sync.WaitGroup
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ips {
				if !ip.Equal(ip4) { // ourselves: Reality cannot point at itself
					if names := s.probe(ctx, ip); names != nil {
						hits <- hit{ip, names}
					}
				}
				st.mu.Lock()
				st.Done++
				st.mu.Unlock()
			}
		}()
	}
	go func() {
		for i := 1; i < 255; i++ {
			ips <- net.IP{ip4[0], ip4[1], ip4[2], byte(i)}
		}
		close(ips)
		wg.Wait()
		close(hits)
	}()
	seen := map[string]bool{}
	var vw sync.WaitGroup
	sem := make(chan struct{}, 8)
	for h := range hits {
		for _, n := range h.names {
			if seen[n] {
				continue
			}
			seen[n] = true
			vw.Add(1)
			sem <- struct{}{}
			go func(n string, ip net.IP) {
				defer vw.Done()
				defer func() { <-sem }()
				if c, ok := s.verify(ctx, n, ip, net24); ok {
					st.mu.Lock()
					st.Found = append(st.Found, c)
					slices.SortFunc(st.Found, rankSites)
					st.mu.Unlock()
				}
			}(n, h.ip)
		}
	}
	vw.Wait()
	st.mu.Lock()
	st.Running = false
	if len(st.Found) > 20 {
		st.Found = st.Found[:20]
	}
	st.mu.Unlock()
}

func rankSites(a, b siteCandidate) int {
	score := func(c siteCandidate) int {
		s := 0
		if c.Status == 200 {
			s += 2
		}
		if c.SameIP {
			s++
		}
		return s
	}
	if d := score(b) - score(a); d != 0 {
		return d
	}
	return a.Ms - b.Ms
}

// serverIPv4 is the address whose /24 is searched: HYP_HOST, resolved if a domain.
func serverIPv4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return ip.To4(), nil
	}
	ips, err := net.LookupIP(host)
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.To4(), nil
		}
	}
	if err == nil {
		err = errors.New("у адреса сервера нет IPv4")
	}
	return nil, err
}
