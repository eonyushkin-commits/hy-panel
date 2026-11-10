// Package sitescan finds and verifies neighbouring sites for Reality.
package sitescan

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

	"github.com/eonyushkin-commits/hy-panel/internal/hostname"
)

// Finding a site for Reality: what the guide did by hand, RealiTLScanner
// over the server's /24 and then a check of each candidate. A good site is
// a neighbour (same /24, so its IP does not stand out next to ours), speaks
// TLS 1.3 with X25519 and HTTP/2, has a valid certificate and answers 200.

// Candidate describes a verified neighbouring site.
type Candidate struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`     // where it answered
	SameIP bool   `json:"sameIP"` // its DNS points at that very address
	Ms     int    `json:"ms"`     // time to the first response
	Status int    `json:"status"` // GET / (redirects are not followed)
}

// scanner holds what tests replace: the port, DNS and trusted roots.
type scanner struct {
	port    string
	resolve func(ctx context.Context, host string) ([]net.IP, error)
	roots   *x509.CertPool // nil: the system's
	timeout time.Duration
}

func newScanner() *scanner {
	return &scanner{port: "443", timeout: 4 * time.Second, resolve: func(ctx context.Context, h string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip4", h)
	}}
}

// BrowserTLS is the handshake Reality needs a site to accept: TLS 1.3 with
// X25519 and HTTP/2. The search and the panel's own site check share it.
func BrowserTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2"}}
}

// probe connects to an address the way RealiTLScanner does and returns the
// names on its certificate if it speaks TLS 1.3 + h2.
func (s *scanner) probe(ctx context.Context, ip net.IP) []string {
	d := &net.Dialer{Timeout: s.timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), s.port))
	if err != nil {
		return nil
	}
	defer c.Close()
	cfg := BrowserTLS()
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
		if hostname.Domain(n) && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// verify checks a domain the way a browser and a probe see it: through its
// own DNS, with certificate verification, TLS 1.3 + X25519 + h2, GET /.
func (s *scanner) verify(ctx context.Context, domain string, found net.IP, net24 *net.IPNet) (Candidate, bool) {
	c := Candidate{Domain: domain, IP: found.String()}
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
	cfg := BrowserTLS()
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

// Result is a search's progress and finds, as the panel shows them.
type Result struct {
	Running bool        `json:"running"`
	Net     string      `json:"net"`
	Done    int         `json:"done"`
	Total   int         `json:"total"`
	Found   []Candidate `json:"found"`
}

// State is the panel's one running (or last) search.
type State struct {
	mu     sync.Mutex
	result Result
}

// Snapshot returns an independent copy of the search progress and results.
func (st *State) Snapshot() Result {
	st.mu.Lock()
	defer st.mu.Unlock()
	r := st.result
	r.Found = append([]Candidate{}, st.result.Found...)
	return r
}

// Start launches a search of server's /24 unless one is already running or
// server is not an IPv4 address. State's zero value is ready to use.
func (st *State) Start(server net.IP) {
	ip4 := server.To4()
	if ip4 == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.result.Running {
		return
	}
	// The subnet and total are set here, not in run, so that a snapshot
	// taken right after Start already describes this search.
	st.result = Result{Running: true, Net: subnet24(ip4).String(), Total: hosts24}
	go newScanner().run(st, ip4)
}

// hosts24 is how many addresses of a /24 are probed: .1 to .254.
const hosts24 = 254

func subnet24(ip4 net.IP) *net.IPNet {
	mask := net.CIDRMask(24, 32)
	return &net.IPNet{IP: ip4.Mask(mask), Mask: mask}
}

// run scans the /24 of server: every neighbour is probed, every name found
// is verified; good ones (200 first, then same IP, then fast) end up in Found.
func (s *scanner) run(st *State, server net.IP) {
	ip4 := server.To4()
	if ip4 == nil {
		st.mu.Lock()
		st.result.Running = false
		st.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	net24 := subnet24(ip4)
	st.mu.Lock()
	st.result.Net, st.result.Total = net24.String(), hosts24
	st.mu.Unlock()

	type hit struct {
		ip    net.IP
		names []string
	}
	ips := make(chan net.IP)
	hits := make(chan hit)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for ip := range ips {
				if !ip.Equal(ip4) { // ourselves: Reality cannot point at itself
					if names := s.probe(ctx, ip); names != nil {
						hits <- hit{ip, names}
					}
				}
				st.mu.Lock()
				st.result.Done++
				st.mu.Unlock()
			}
		})
	}
	go func() {
		for i := 1; i <= hosts24; i++ {
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
			sem <- struct{}{}
			vw.Go(func() {
				defer func() { <-sem }()
				if c, ok := s.verify(ctx, n, h.ip, net24); ok {
					st.mu.Lock()
					st.result.Found = append(st.result.Found, c)
					slices.SortFunc(st.result.Found, rank)
					st.mu.Unlock()
				}
			})
		}
	}
	vw.Wait()
	st.mu.Lock()
	st.result.Running = false
	if len(st.result.Found) > 20 {
		st.result.Found = st.result.Found[:20]
	}
	st.mu.Unlock()
}

// rank orders candidates best first: 200 answers, then same IP, then speed.
func rank(a, b Candidate) int {
	score := func(c Candidate) int {
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

// ServerIPv4 is the address whose /24 is searched: HYP_HOST, resolved if a domain.
func ServerIPv4(host string) (net.IP, error) {
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
