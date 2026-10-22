package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"tailscale.com/net/netmon"
)

// Name lookups by the daemon itself: Tailscale's servers, GitHub for the
// update check, the coordination server, whatever goes through the HTTP
// proxy.
//
// The PS5 has no resolv.conf, so Go asks 127.0.0.1:53. That only works on a
// console that runs a DNS payload, which most jailbreak setups do and some do
// not. Rather than depend on it, the daemon uses the first of these that
// answers: the local DNS payload, the router, a public resolver.
//
// A resolver can also answer for most names and still fail for one, by
// blocking or breaking it (SERVFAIL). A console whose router does that for a
// private coordination server could never reach it, so every query that the
// plain server cannot answer is asked again of a public DNS-over-HTTPS
// endpoint. The console's own DNS settings are not touched: only this
// process looks names up this way.

// dnsLocal is where a DNS payload on the console listens. A variable so that
// a test build can pretend there is none.
var dnsLocal = "127.0.0.1:53"

// dnsPublic are used when neither the console nor the router answers.
var dnsPublic = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

const (
	dnsRecheckGood = 5 * time.Minute  // how long a working server is kept
	dnsRecheckBad  = 20 * time.Second // how soon to look again when none works
	dnsProbeWait   = 1200 * time.Millisecond
	plainWait      = 2 * time.Second  // how long a plain server may take with a query
	dohWait        = 3 * time.Second  // how long a DNS-over-HTTPS server may take
	dnsPipeIdle    = 30 * time.Second // an idle resolver connection is dropped
	dnsDoHLogGap   = time.Minute      // how often the fallback may be logged
	maxDNSReply    = 4096
)

// dohEndpoints are the public DNS-over-HTTPS servers a query is taken to
// when no plain server can answer it. The address is dialed directly and the
// name is carried as the TLS server name, so the endpoint itself never needs
// a name lookup of its own.
var dohEndpoints = []struct {
	host string
	path string
	ips  []string
}{
	{"cloudflare-dns.com", "/dns-query", []string{"1.1.1.1", "1.0.0.1"}},
	{"dns.google", "/dns-query", []string{"8.8.8.8", "8.8.4.4"}},
}

type dnsPicker struct {
	logf func(format string, args ...any)
	// candidates lists the servers to try, in order of preference.
	candidates func() []string
	// probe reports whether a server answers queries.
	probe func(ctx context.Context, server string) bool
	// plainAsk forwards one wire-format query to a plain server. A variable
	// so that tests can stand in for the network.
	plainAsk func(ctx context.Context, network, server string, query []byte) ([]byte, error)
	// dohAsk asks a public DNS-over-HTTPS endpoint the same query.
	dohAsk func(ctx context.Context, query []byte) ([]byte, error)

	mu      sync.Mutex
	server  string
	working bool
	checked time.Time
	lastDoH time.Time
}

func newDNSPicker(logf func(format string, args ...any)) *dnsPicker {
	return &dnsPicker{
		logf:       logf,
		candidates: dnsCandidates,
		probe:      dnsAnswers,
		plainAsk:   dnsPlainAsk,
		dohAsk:     dnsDoHAsk,
	}
}

// dnsCandidates returns the local DNS payload, the router and the public
// resolvers, in that order.
func dnsCandidates() []string {
	list := []string{dnsLocal}
	if gw, _, ok := netmon.LikelyHomeRouterIP(); ok && gw.IsValid() {
		list = append(list, net.JoinHostPort(gw.String(), "53"))
	}
	return append(list, dnsPublic...)
}

// pick returns the server to ask. The choice is kept for a while, so the
// candidates are not probed for every lookup.
func (p *dnsPicker) pick(ctx context.Context) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	keep := dnsRecheckBad
	if p.working {
		keep = dnsRecheckGood
	}
	if p.server != "" && time.Since(p.checked) < keep {
		return p.server
	}
	candidates := p.candidates()
	chosen, working := candidates[0], false
	for _, c := range candidates {
		if p.probe(ctx, c) {
			chosen, working = c, true
			break
		}
	}
	if chosen != p.server || working != p.working {
		switch {
		case !working:
			p.logf("DNS: no server answers (tried %v); name lookups will fail until one does", candidates)
		case chosen == candidates[0]:
			p.logf("DNS: using the console's own DNS at %s", chosen)
		default:
			p.logf("DNS: nothing answers at %s; using %s instead (in order of preference: %v)", candidates[0], chosen, candidates)
		}
	}
	p.server, p.working, p.checked = chosen, working, time.Now()
	return chosen
}

// reset makes the next lookup choose again, for when the network changed.
func (p *dnsPicker) reset() {
	p.mu.Lock()
	p.checked = time.Time{}
	p.mu.Unlock()
}

// dial is the resolver's Dial. Whatever address Go wants to ask, the query
// is answered here: first from the picked plain server, and when that fails
// or cannot make sense of the name (SERVFAIL), from a public
// DNS-over-HTTPS endpoint instead.
func (p *dnsPicker) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	server := p.pick(ctx)
	client, serverSide := net.Pipe()
	go p.serveResolver(ctx, network, server, serverSide)
	return client, nil
}

// serveResolver answers DNS on a connection handed to Go's resolver: read a
// query, answer it, until the resolver is done with the connection.
func (p *dnsPicker) serveResolver(ctx context.Context, network, server string, c net.Conn) {
	defer c.Close()
	for {
		c.SetReadDeadline(time.Now().Add(dnsPipeIdle))
		var query []byte
		if network == "tcp" {
			var l uint16
			if err := binary.Read(c, binary.BigEndian, &l); err != nil {
				return
			}
			query = make([]byte, l)
			if _, err := io.ReadFull(c, query); err != nil {
				return
			}
		} else {
			buf := make([]byte, 1500)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			query = buf[:n]
		}
		if len(query) < 12 {
			continue
		}
		reply := p.forwardQuery(ctx, network, server, query)
		if network == "tcp" {
			if err := binary.Write(c, binary.BigEndian, uint16(len(reply))); err != nil {
				return
			}
		}
		if _, err := c.Write(reply); err != nil {
			return
		}
	}
}

// forwardQuery answers one query: from the plain server only when it has a
// real answer for it. Every other outcome — silence, an error, or a
// negative answer (NXDOMAIN, SERVFAIL, or "no error but no addresses") —
// is asked over DNS-over-HTTPS instead: on networks that intercept plain
// DNS, a negative answer is exactly what the interceptor hands back for a
// name it refuses to resolve, and only a second opinion over HTTPS can
// tell a lie from the truth. When DoH cannot answer either, the plain
// server's reply (or a clean server failure) is returned, so nothing is
// invented.
func (p *dnsPicker) forwardQuery(ctx context.Context, network, server string, query []byte) []byte {
	reply, plainErr := p.plainAsk(ctx, network, server, query)
	if plainErr == nil && dnsRcode(reply) == 0 && dnsAnswerCount(reply) > 0 {
		return reply // the server really answered this name
	}
	if p.dohAsk == nil {
		if plainErr != nil {
			return dnsServfail(query)
		}
		return reply
	}
	viaDoH, dohErr := p.dohAsk(ctx, query)
	reason := dnsPlainReason(plainErr, reply)
	if dohErr == nil && len(viaDoH) >= 12 {
		copy(viaDoH[0:2], query[0:2]) // the answer must carry this query's id
		p.logDoH(server, reason, nil)
		return viaDoH
	}
	p.logDoH(server, reason, dohErr)
	if plainErr == nil {
		return reply // nothing better available
	}
	return dnsServfail(query)
}

// dnsPlainReason says why a plain server's answer was not believed.
func dnsPlainReason(plainErr error, reply []byte) string {
	switch {
	case plainErr != nil:
		return plainErr.Error()
	case dnsRcode(reply) == 2:
		return "answered SERVFAIL"
	case dnsRcode(reply) == 3:
		return "answered NXDOMAIN"
	default:
		return "answered with no addresses"
	}
}

// dnsAnswerCount is how many records a reply carries in its answer section.
func dnsAnswerCount(reply []byte) int {
	if len(reply) < 8 {
		return 0
	}
	return int(binary.BigEndian.Uint16(reply[6:8]))
}

// logDoH mentions the fallback in the log, without repeating it every
// few seconds while a resolver is misbehaving. dohErr is nil when the
// query went over HTTPS and came back; otherwise it says why that failed
// too, which is worth being able to see from a diagnostics file.
func (p *dnsPicker) logDoH(server, plainReason string, dohErr error) {
	p.mu.Lock()
	stamp := time.Now()
	fresh := stamp.Sub(p.lastDoH) >= dnsDoHLogGap
	if fresh {
		p.lastDoH = stamp
	}
	p.mu.Unlock()
	if !fresh {
		return
	}
	if dohErr != nil {
		p.logf("DNS: %s could not answer a query (%s); DNS-over-HTTPS failed too (%v)", server, plainReason, dohErr)
		return
	}
	p.logf("DNS: %s could not answer a query (%s); asked over HTTPS instead", server, plainReason)
}

// dnsRcode is the reply's return code; 2 means SERVFAIL, a server that
// could not make the lookup even though it is answering for other names.
func dnsRcode(reply []byte) int {
	if len(reply) < 4 {
		return 2
	}
	return int(reply[3] & 0x0f)
}

// dnsServfail builds a server-failure answer to query, echoing its id.
func dnsServfail(query []byte) []byte {
	reply := make([]byte, 12)
	copy(reply, query[:12])
	reply[2] = 0x81 // response, recursion available
	reply[3] = 0x02 // SERVFAIL
	return reply
}

// dnsPlainAsk forwards the wire-format query to a plain DNS server and
// returns its reply.
func dnsPlainAsk(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, plainWait)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if network == "tcp" {
		if err := binary.Write(c, binary.BigEndian, uint16(len(query))); err != nil {
			return nil, err
		}
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	if network == "tcp" {
		var l uint16
		if err := binary.Read(c, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		if l < 12 || int(l) > maxDNSReply {
			return nil, errors.New("bad DNS reply length")
		}
		reply := make([]byte, l)
		if _, err := io.ReadFull(c, reply); err != nil {
			return nil, err
		}
		return reply, nil
	}
	buf := make([]byte, maxDNSReply)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, errors.New("short DNS reply")
	}
	return buf[:n], nil
}

// dnsDoHAsk asks a public DNS-over-HTTPS endpoint with the wire-format
// query (RFC 8484) and returns its reply. Each endpoint's published
// addresses are dialed directly, carrying the endpoint's name as the TLS
// server name, so no name lookup is needed to reach the resolvers.
func dnsDoHAsk(ctx context.Context, query []byte) ([]byte, error) {
	var lastErr error
	for _, ep := range dohEndpoints {
		for _, ip := range ep.ips {
			reply, err := doHQuery(ctx, ep.host, ep.path, ip, query)
			if err != nil {
				lastErr = err
				continue
			}
			return reply, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS-over-HTTPS endpoints")
	}
	return nil, lastErr
}

func doHQuery(ctx context.Context, host, path, ip string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dohWait)
	defer cancel()
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{ServerName: host},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host+path, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSReply+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	if len(body) < 12 || len(body) > maxDNSReply {
		return nil, errors.New("bad DNS-over-HTTPS reply")
	}
	return body, nil
}

// install makes every name lookup in the process go through the picker.
func (p *dnsPicker) install() {
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: p.dial}
}

// dnsAnswers asks server for the address of a name that certainly exists
// and reports whether a proper answer came back.
func dnsAnswers(ctx context.Context, server string) bool {
	ctx, cancel := context.WithTimeout(ctx, dnsProbeWait)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsProbeWait))
	query := dnsQuery(uint16(time.Now().UnixNano()), "github.com")
	if _, err := c.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return false
	}
	return dnsReplyOK(query, buf[:n])
}

// dnsQuery builds a query for the IPv4 address of name.
func dnsQuery(id uint16, name string) []byte {
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[0:], id)
	q[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(q[4:], 1)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	return append(q, 0, 0, 1, 0, 1) // root label, type A, class IN
}

// dnsReplyOK reports whether reply is a successful answer to query.
func dnsReplyOK(query, reply []byte) bool {
	if len(reply) < 12 || reply[0] != query[0] || reply[1] != query[1] {
		return false
	}
	isResponse := reply[2]&0x80 != 0
	rcode := reply[3] & 0x0f
	answers := binary.BigEndian.Uint16(reply[6:])
	return isResponse && rcode == 0 && answers > 0
}

// describe says in words which server is in use, for the status page. It
// does not probe.
func (p *dnsPicker) describe() string {
	p.mu.Lock()
	server, working := p.server, p.working
	p.mu.Unlock()
	if server == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
	}
	if !working {
		return "no plain server; using DNS-over-HTTPS"
	}
	switch {
	case server == dnsLocal:
		return host + " (DNS payload on this console)"
	case slices.Contains(dnsPublic, server):
		return host + " (public resolver)"
	default:
		return host + " (router)"
	}
}
