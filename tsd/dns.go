package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/dnscache"
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
	plainWait      = 2 * time.Second         // how long a plain server may take with a query
	dohWait        = 2500 * time.Millisecond // how long a DNS-over-HTTPS server may take
	dnsPipeIdle    = 30 * time.Second        // an idle resolver connection is dropped
	dnsDoHLogGap   = time.Minute             // how often the fallback for one name may be logged
	dnsFixedLogGap = 10 * time.Minute        // how often a fixed address may be mentioned
	maxDNSReply    = 4096
)

// The whole answer must fit inside the 5 s Go's resolver allows one attempt
// at one name server: plain server (plainWait) first, then all DNS-over-HTTPS
// endpoints at once (dohWait). Anything slower arrives after the resolver has
// hung up and re-dialled, so the answer is never read — which is how a
// serially-probed endpoint got a control lookup killed at exactly the DNS
// cache's 10 s budget twice over.

// dohEndpoints are the public DNS-over-HTTPS servers a query is taken to
// when no plain server can answer it. The address is dialed directly and the
// name is carried as the TLS server name, so the endpoint itself never needs
// a name lookup of its own. All of them are asked at once, not one after
// another: the answer has to arrive while the resolver is still waiting.
type dohEndpoint struct {
	host string
	path string
	ips  []string
}

var dohEndpoints = []dohEndpoint{
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
	// endpoints overrides dohEndpoints for dohAsk. Tests use it.
	endpoints []dohEndpoint

	mu        sync.Mutex
	server    string
	working   bool
	checked   time.Time
	fixed     map[string]netip.Addr // names answered from set addresses
	lastDoH   map[string]time.Time  // per-name: last time the fallback was logged
	lastFixed map[string]time.Time  // per-name: last time a fixed address was logged
}

func newDNSPicker(logf func(format string, args ...any)) *dnsPicker {
	p := &dnsPicker{
		logf:       logf,
		candidates: dnsCandidates,
		probe:      dnsAnswers,
		plainAsk:   dnsPlainAsk,
	}
	p.dohAsk = p.dohAskDefault
	return p
}

// dohAskDefault is the real fallback: every endpoint asked at once.
func (p *dnsPicker) dohAskDefault(ctx context.Context, query []byte) ([]byte, error) {
	endpoints := p.endpoints
	if endpoints == nil {
		endpoints = dohEndpoints
	}
	return dohRace(ctx, query, endpoints, doHQuery)
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
//
// Go frames the exchange on a custom-Dial connection with a 2-byte length
// prefix on EVERY network, writes and reads alike (verified against Go's
// behaviour: an unprefixed answer on a "udp" pipe is never read and the
// lookup dies in i/o timeout; the same answer with the prefix resolves at
// once). So the prefix comes off on the way in and goes back on the way
// out here, whatever the network claims; only the servers actually asked
// over the real wire get the plain RFC 1035 bytes.
func (p *dnsPicker) serveResolver(ctx context.Context, network, server string, c net.Conn) {
	defer c.Close()
	for {
		c.SetReadDeadline(time.Now().Add(dnsPipeIdle))
		var l uint16
		if err := binary.Read(c, binary.BigEndian, &l); err != nil {
			return
		}
		if l < 12 || int(l) > maxDNSReply {
			return // not a framing Go's resolver uses; stop this connection
		}
		query := make([]byte, l)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		reply := p.forwardQuery(ctx, network, server, query)
		if err := binary.Write(c, binary.BigEndian, uint16(len(reply))); err != nil {
			return
		}
		if _, err := c.Write(reply); err != nil {
			return
		}
	}
}

// forwardQuery answers one query. A name with an address set on the status
// page is answered from it at once, with no name server asked at all.
// Otherwise the query goes to the plain server and is believed only when it
// has a real answer for it. Every other outcome — silence, an error, or a
// negative answer (NXDOMAIN, SERVFAIL, or "no error but no addresses") — is
// asked over DNS-over-HTTPS instead: on networks that intercept plain DNS, a
// negative answer is exactly what the interceptor hands back for a name it
// refuses to resolve, and only a second opinion over HTTPS can tell a lie
// from the truth. When DoH cannot answer either, the plain server's reply (or
// a clean server failure) is returned, so nothing is invented.
func (p *dnsPicker) forwardQuery(ctx context.Context, network, server string, query []byte) []byte {
	name, _, haveName := dnsParseQuery(query)
	if !haveName {
		name = "(unreadable query)"
	}
	if reply, fixed := p.fixedReply(query); fixed {
		return reply
	}
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
	if dohErr == nil {
		copy(viaDoH[0:2], query[0:2]) // the answer must carry this query's id
		p.logDoH(name, server, reason, nil)
		return viaDoH
	}
	p.logDoH(name, server, reason, dohErr)
	if plainErr == nil {
		return reply // nothing better available
	}
	return dnsServfail(query)
}

// setFixedNames sets the names that are answered straight from an address
// given on the status page, without asking any name server — for networks
// whose DNS refuses to resolve a name this app needs, usually the user's own
// coordination server. Entries whose address cannot be read are skipped; the
// settings form has already refused them.
func (p *dnsPicker) setFixedNames(m map[string]string) {
	fixed := make(map[string]netip.Addr, len(m))
	for name, addr := range m {
		if a, err := netip.ParseAddr(strings.TrimSpace(addr)); err == nil {
			fixed[dnsFixName(name)] = a
		}
	}
	p.mu.Lock()
	p.fixed = fixed
	p.mu.Unlock()
}

// fixedReply answers query from a fixed address, reporting whether the name
// is one of them. The right record kind gets the address; the wrong one gets
// a clean empty answer, so Go's resolver finds the name and stops asking.
func (p *dnsPicker) fixedReply(query []byte) ([]byte, bool) {
	p.mu.Lock()
	fixed := p.fixed
	p.mu.Unlock()
	if len(fixed) == 0 {
		return nil, false
	}
	name, qs, ok := dnsParseQuery(query)
	if !ok {
		return nil, false
	}
	addr, mapped := fixed[name]
	if !mapped {
		return nil, false
	}
	var addrs []netip.Addr
	switch {
	case qs[0].Type == dnsmessage.TypeA && addr.Is4():
		addrs = append(addrs, addr)
	case qs[0].Type == dnsmessage.TypeAAAA && addr.Is6():
		addrs = append(addrs, addr)
	}
	p.logFixed(name, addr, len(addrs) > 0)
	return dnsBuildReply(query, qs, addrs), true
}

// dnsFixName is the key form for fixed names: lower case, no trailing dot.
func dnsFixName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// dnsParseQuery reads a query's question so it can be answered or checked.
func dnsParseQuery(query []byte) (name string, qs []dnsmessage.Question, ok bool) {
	var pr dnsmessage.Parser
	if _, err := pr.Start(query); err != nil {
		return "", nil, false
	}
	qs, err := pr.AllQuestions()
	if err != nil || len(qs) == 0 {
		return "", nil, false
	}
	return dnsFixName(qs[0].Name.String()), qs, true
}

// dnsBuildReply builds a response to query, echoing its question, with
// addrs (possibly none) as the answers.
func dnsBuildReply(query []byte, qs []dnsmessage.Question, addrs []netip.Addr) []byte {
	var fail = func() []byte { return dnsServfail(query) }
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: binary.BigEndian.Uint16(query[:2]), RecursionDesired: true, RecursionAvailable: true, Response: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return fail()
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return fail()
		}
	}
	if err := b.StartAnswers(); err != nil {
		return fail()
	}
	for _, a := range addrs {
		h := dnsmessage.ResourceHeader{Name: qs[0].Name, Class: dnsmessage.ClassINET, TTL: 300}
		var err error
		if a.Is4() {
			err = b.AResource(h, dnsmessage.AResource{A: a.As4()})
		} else {
			err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
		if err != nil {
			return fail()
		}
	}
	out, err := b.Finish()
	if err != nil {
		return fail()
	}
	return out
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

// logDoH mentions the fallback for one name in the log, without repeating it
// every few seconds while a resolver is misbehaving. The name is in the line:
// a diagnostics file has to say which lookup needed the fallback and which
// one the network is really refusing. dohErr is nil when the query went over
// HTTPS and came back; otherwise it says why that failed too.
func (p *dnsPicker) logDoH(name, server, plainReason string, dohErr error) {
	p.mu.Lock()
	stamp := time.Now()
	if p.lastDoH == nil {
		p.lastDoH = map[string]time.Time{}
	}
	fresh := stamp.Sub(p.lastDoH[name]) >= dnsDoHLogGap
	if fresh {
		p.lastDoH[name] = stamp
		for k, t := range p.lastDoH {
			if stamp.Sub(t) > 10*time.Minute {
				delete(p.lastDoH, k)
			}
		}
	}
	p.mu.Unlock()
	if !fresh {
		return
	}
	if dohErr != nil {
		p.logf("DNS: %s: %s could not answer (%s); DNS-over-HTTPS failed too (%v)", name, server, plainReason, dohErr)
		return
	}
	p.logf("DNS: %s: %s could not answer (%s); asked over HTTPS instead", name, server, plainReason)
}

// logFixed notes that a name was answered from an address set on the status
// page. It says so once every so often per name, so the diagnostics show the
// path a lookup took without filling the log.
func (p *dnsPicker) logFixed(name string, addr netip.Addr, used bool) {
	p.mu.Lock()
	stamp := time.Now()
	if p.lastFixed == nil {
		p.lastFixed = map[string]time.Time{}
	}
	fresh := stamp.Sub(p.lastFixed[name]) >= dnsFixedLogGap
	if fresh {
		p.lastFixed[name] = stamp
	}
	p.mu.Unlock()
	if !fresh {
		return
	}
	if used {
		p.logf("DNS: %s: answered from the address you set (%v)", name, addr)
	} else {
		p.logf("DNS: %s: no address of that record kind is set (you set %v); answered empty", name, addr)
	}
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

// dohRace asks every DNS-over-HTTPS endpoint at once (RFC 8484) and returns
// the first proper answer. Serial probing was the bug: with a plain server
// that takes its full 2 s to say nothing, an endpoint probed one after
// another could not answer inside the 5 s Go's resolver gives a single
// attempt, so every attempt died at the deadline and the control lookup
// failed at exactly the DNS cache's outer timeout, twice — and fell through
// to the DERP bootstrap DNS, which cannot know a private server's name.
//
// Each endpoint's published addresses are dialed directly, carrying the
// endpoint's name as the TLS server name, so no name lookup is needed to
// reach the resolvers. An endpoint that answers with anything other than a
// real answer — an interceptor's error page delivered over port 443, say —
// counts as failing: a lie is not an answer.
func dohRace(ctx context.Context, query []byte, endpoints []dohEndpoint, ask func(ctx context.Context, host, path, ip string, query []byte) ([]byte, error)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dohWait)
	defer cancel()
	type outcome struct {
		reply []byte
		err   error
	}
	ch := make(chan outcome, 16)
	n := 0
	for _, ep := range endpoints {
		for _, ip := range ep.ips {
			n++
			go func(ep dohEndpoint, ip string) {
				reply, err := ask(ctx, ep.host, ep.path, ip, query)
				if err == nil {
					if perr := dnsAnswerProblems(query, reply, ep.host); perr != nil {
						reply, err = nil, perr
					}
				}
				ch <- outcome{reply, err}
			}(ep, ip)
		}
	}
	var errs []string
	for range n {
		o := <-ch
		if o.err == nil {
			return o.reply, nil
		}
		errs = append(errs, o.err.Error())
	}
	if n == 0 {
		return nil, errors.New("no DNS-over-HTTPS endpoints")
	}
	slices.Sort(errs)
	return nil, errors.New(strings.Join(errs, "; "))
}

// dnsAnswerProblems reports why reply is not an answer to query that may be
// handed to the resolver, naming the endpoint that sent it. A body that is
// not a DNS message at all, a refusal, and an empty answer for a name the
// whole point was to resolve all count as problems.
func dnsAnswerProblems(query, reply []byte, from string) error {
	var pr dnsmessage.Parser
	h, err := pr.Start(reply)
	if err != nil {
		return fmt.Errorf("%s: not a DNS answer (%v)", from, err)
	}
	if !h.Response {
		return fmt.Errorf("%s: sent a query, not an answer", from)
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("%s: answered %v", from, h.RCode)
	}
	qs, err := pr.AllQuestions()
	if err != nil || len(qs) == 0 {
		return fmt.Errorf("%s: answer without a question", from)
	}
	name, q, ok := dnsParseQuery(query)
	if !ok || dnsFixName(qs[0].Name.String()) != name || qs[0].Type != q[0].Type {
		return fmt.Errorf("%s: answer for another name or record kind", from)
	}
	answers := 0
	for {
		a, err := pr.Answer()
		if err != nil {
			break
		}
		if a.Header.Type == qs[0].Type {
			answers++
		}
	}
	if answers == 0 {
		return fmt.Errorf("%s: answered with no addresses", from)
	}
	return nil
}

// checkControl resolves the coordination server's name as soon as it is
// asked for, so a diagnostics file says at once whether the daemon can find
// its own server instead of waiting for Tailscale to time out twice.
func (p *dnsPicker) checkControl(controlURL string) {
	if controlURL == "" {
		return
	}
	u, err := url.Parse(controlURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	host := u.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		p.logf("DNS: the coordination server %s cannot be resolved: %v", host, err)
		return
	}
	p.logf("DNS: the coordination server %s resolves to %v", host, addrs)
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
// Both places that matter: Go's default resolver, and the DNS cache
// Tailscale's control client builds from. The control client does not ask
// net.DefaultResolver at all (control/controlclient/direct.go copies
// dnscache's forwarder at startup), so installing only the default
// resolver leaves coordination-server lookups on the plain path — which
// is exactly how a console whose network intercepts DNS ends up asking
// DERP servers to resolve a Headscale name, which they can only ever
// refuse: their bootstrap-dns map contains Tailscale's own names only.
func (p *dnsPicker) install() {
	r := &net.Resolver{PreferGo: true, Dial: p.dial}
	net.DefaultResolver = r
	dnscache.Get().Forward = r
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
