package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/dnscache"
)

func testPicker(t *testing.T, candidates []string, answering map[string]bool) (*dnsPicker, *[]string, *[]string) {
	var logs, probed []string
	p := &dnsPicker{
		logf:       func(format string, args ...any) { logs = append(logs, format) },
		candidates: func() []string { return candidates },
		probe: func(ctx context.Context, server string) bool {
			probed = append(probed, server)
			return answering[server]
		},
	}
	return p, &logs, &probed
}

func TestDNSPicker(t *testing.T) {
	candidates := []string{"127.0.0.1:53", "192.168.1.1:53", "1.1.1.1:53"}
	answering := map[string]bool{"127.0.0.1:53": true, "192.168.1.1:53": true, "1.1.1.1:53": true}
	p, logs, probed := testPicker(t, candidates, answering)
	ctx := context.Background()

	// The console's own DNS is preferred, and the choice is kept.
	if got := p.pick(ctx); got != "127.0.0.1:53" {
		t.Fatalf("picked %s", got)
	}
	p.pick(ctx)
	if len(*probed) != 1 {
		t.Errorf("probed %v; the choice should have been kept", *probed)
	}

	// No DNS payload: the router is used, and that is logged.
	answering["127.0.0.1:53"] = false
	p.reset()
	if got := p.pick(ctx); got != "192.168.1.1:53" {
		t.Errorf("without a local DNS: picked %s", got)
	}
	if last := (*logs)[len(*logs)-1]; !strings.Contains(last, "instead") {
		t.Errorf("log: %q", last)
	}

	// Nor the router: a public resolver.
	answering["192.168.1.1:53"] = false
	p.reset()
	if got := p.pick(ctx); got != "1.1.1.1:53" {
		t.Errorf("without local DNS or router: picked %s", got)
	}

	// Nothing at all: stay with the first, and look again soon.
	answering["1.1.1.1:53"] = false
	p.reset()
	if got := p.pick(ctx); got != "127.0.0.1:53" {
		t.Errorf("with nothing answering: picked %s", got)
	}
	if p.working {
		t.Error("the picker thinks it has a working server")
	}
	before := len(*probed)
	p.checked = time.Now().Add(-dnsRecheckBad - time.Second)
	answering["127.0.0.1:53"] = true
	if got := p.pick(ctx); got != "127.0.0.1:53" || len(*probed) == before || !p.working {
		t.Errorf("after the short wait: picked %s, working %v", got, p.working)
	}
}

func TestDNSQueryAndReply(t *testing.T) {
	q := dnsQuery(0x1234, "github.com")
	want := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 'g', 'i', 't', 'h', 'u', 'b', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if string(q) != string(want) {
		t.Fatalf("query = % x", q)
	}
	reply := func(id0, id1, flags2, flags3 byte, answers byte) []byte {
		return []byte{id0, id1, flags2, flags3, 0, 1, 0, answers, 0, 0, 0, 0}
	}
	for name, tt := range map[string]struct {
		r    []byte
		want bool
	}{
		"good answer":        {reply(0x12, 0x34, 0x81, 0x80, 2), true},
		"another query's id": {reply(0x12, 0x35, 0x81, 0x80, 2), false},
		"server failure":     {reply(0x12, 0x34, 0x81, 0x82, 0), false},
		"no such name":       {reply(0x12, 0x34, 0x81, 0x83, 0), false},
		"no answers":         {reply(0x12, 0x34, 0x81, 0x80, 0), false},
		"not a response":     {reply(0x12, 0x34, 0x01, 0x00, 1), false},
		"too short":          {[]byte{0x12, 0x34}, false},
	} {
		if got := dnsReplyOK(q, tt.r); got != tt.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

// A real exchange over UDP with a stand-in server, and a port where nothing
// answers.
func TestDNSAnswers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			r := append([]byte(nil), buf[:n]...)
			r[2], r[3], r[7] = 0x81, 0x80, 1 // response, no error, one answer
			pc.WriteTo(r, from)
		}
	}()
	if !dnsAnswers(context.Background(), pc.LocalAddr().String()) {
		t.Error("a server that answers was reported as silent")
	}

	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	start := time.Now()
	if dnsAnswers(context.Background(), silent.LocalAddr().String()) {
		t.Error("a silent server was reported as answering")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("the probe took %v", time.Since(start))
	}
}

// replyTo builds a reply to query with the given flags (response bit set)
// and rcode.
func replyTo(query []byte, rcode byte) []byte {
	r := append([]byte(nil), query[:12]...)
	r[2] = 0x81
	r[3] = rcode
	r[6], r[7] = 0, 1 // one answer
	return r
}

// noAnswerTo is the other lie a blocking resolver or a transparent
// interceptor hands back: "no error, no addresses".
func noAnswerTo(query []byte) []byte {
	r := make([]byte, 12)
	copy(r, query[:12])
	return r
}

// The plain server answers for most names and fails one, the way a resolver
// blocking or breaking a single name does; and it fails everything, the way
// a dead one does. Both cases must fall back to DNS-over-HTTPS.
func TestForwardQuery(t *testing.T) {
	ctx := context.Background()
	fakeDoH := func(ctx context.Context, query []byte) ([]byte, error) {
		r := replyTo(query, 0)
		r[11] = 0xAA // a mark to recognise
		return r, nil
	}

	// The plain server can answer: its reply is passed through untouched.
	p := &dnsPicker{
		logf:     func(string, ...any) {},
		plainAsk: func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return replyTo(q, 0), nil },
		dohAsk:   fakeDoH,
	}
	q := dnsQuery(7, "github.com")
	if r := p.forwardQuery(ctx, "udp", "1.1.1.1:53", q); r[11] != 0 {
		t.Error("the plain server's answer was not passed through")
	}

	// NXDOMAIN is a negative answer: on an intercepted network it may be a
	// lie, so it is checked with DNS-over-HTTPS, which answers for real.
	// (plainAsk and dohAsk are now captured in the picker below.)
	pLie := &dnsPicker{
		logf:     func(string, ...any) {},
		plainAsk: func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return replyTo(q, 3), nil },
		dohAsk:   fakeDoH,
	}
	if r := pLie.forwardQuery(ctx, "udp", "1.1.1.1:53", q); r[11] != 0xAA {
		t.Error("NXDOMAIN was believed without asking over HTTPS")
	}

	// "No error, no addresses" — the other way a blocking resolver lies —
	// is checked the same way, and so is the same reply when HTTPS fails
	// too: the plain server's reply comes back, because nothing better
	// exists and nothing is invented.
	pLie.plainAsk = func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return noAnswerTo(q), nil }
	if r := pLie.forwardQuery(ctx, "udp", "1.1.1.1:53", q); r[11] != 0xAA {
		t.Error("an empty answer was believed without asking over HTTPS")
	}
	pLie.dohAsk = func(ctx context.Context, q []byte) ([]byte, error) { return nil, errors.New("no route") }
	if r := pLie.forwardQuery(ctx, "udp", "1.1.1.1:53", q); dnsRcode(r) != 0 || dnsAnswerCount(r) != 0 {
		t.Errorf("a failing HTTPS check changed the reply: % x", r)
	}

	// SERVFAIL for this one name: asked over HTTPS, and the answer carries
	// the id of the original query.
	p.plainAsk = func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return replyTo(q, 2), nil }
	r := p.forwardQuery(ctx, "udp", "192.168.0.1:53", q)
	if r[11] != 0xAA || r[0] != q[0] || r[1] != q[1] {
		t.Errorf("SERVFAIL not resolved over HTTPS: % x", r)
	}

	// Plain server refuses outright: also asked over HTTPS.
	p.plainAsk = func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return nil, errors.New("refused") }
	if r := p.forwardQuery(ctx, "udp", "192.168.0.1:53", q); r[11] != 0xAA {
		t.Error("a refused plain server did not fall back")
	}

	// Both fail: a clean SERVFAIL of our own, so the resolver is not left
	// waiting for an answer that will not come.
	p.dohAsk = func(ctx context.Context, q []byte) ([]byte, error) { return nil, errors.New("no route") }
	r = p.forwardQuery(ctx, "udp", "192.168.0.1:53", q)
	if dnsRcode(r) != 2 || r[0] != q[0] {
		t.Errorf("both failing should end in SERVFAIL: % x", r)
	}

	// A fallback is logged, and its failure is logged too, but neither for
	// every query. A fresh picker, so the earlier fallbacks in this test do
	// not count as the recent one.
	var logs int
	p2 := &dnsPicker{
		logf:     func(string, ...any) { logs++ },
		plainAsk: func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return nil, errors.New("refused") },
		dohAsk:   fakeDoH,
	}
	for i := 0; i < 3; i++ {
		p2.forwardQuery(ctx, "udp", "192.168.0.1:53", q)
	}
	if logs != 1 {
		t.Errorf("the fallback was logged %d times, want once", logs)
	}
	var failLogs int
	p3 := &dnsPicker{
		logf:     func(string, ...any) { failLogs++ },
		plainAsk: func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return nil, errors.New("refused") },
		dohAsk:   func(ctx context.Context, q []byte) ([]byte, error) { return nil, errors.New("no route") },
	}
	for i := 0; i < 3; i++ {
		p3.forwardQuery(ctx, "udp", "192.168.0.1:53", q)
	}
	if failLogs != 1 {
		t.Errorf("the failing fallback was logged %d times, want once", failLogs)
	}
}

// A query through the connection handed to Go's resolver: the resolver
// writes a DNS query, and an answer comes back with the right id, over both
// UDP (datagram) and TCP (length-prefixed) framing.
func TestDialResolverConnection(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		p := &dnsPicker{
			logf:       func(string, ...any) {},
			candidates: func() []string { return []string{"1.1.1.1:53"} },
			probe:      func(context.Context, string) bool { return true },
			plainAsk:   func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return replyTo(q, 2), nil },
			dohAsk: func(ctx context.Context, q []byte) ([]byte, error) {
				return replyTo(q, 0), nil
			},
		}
		c, err := p.dial(context.Background(), network, "nowhere:53")
		if err != nil {
			t.Fatal(err)
		}
		q := dnsQuery(0xABCD, "example.com")
		if network == "tcp" {
			binary.Write(c, binary.BigEndian, uint16(len(q)))
		}
		c.Write(q)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var buf []byte
		if network == "tcp" {
			var l uint16
			if err := binary.Read(c, binary.BigEndian, &l); err != nil {
				t.Fatalf("tcp: length: %v", err)
			}
			buf = make([]byte, l)
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("tcp: body: %v", err)
			}
		} else {
			raw := make([]byte, 1500)
			n, err := c.Read(raw)
			if err != nil {
				t.Fatalf("%s: read: %v", network, err)
			}
			buf = raw[:n]
		}
		c.Close()
		if dnsRcode(buf) != 0 || buf[0] != 0xAB || buf[1] != 0xCD {
			t.Errorf("%s: bad reply % x", network, buf)
		}
	}
}

// The real DNS-over-HTTPS path, if this machine has a network.
func TestDoHLive(t *testing.T) {
	if _, err := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second); err != nil {
		t.Skip("no network to reach a DNS-over-HTTPS endpoint")
	}
	p := newDNSPicker(t.Logf)
	q := dnsQuery(1, "tailscale.com")
	reply, err := p.dohAsk(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if dnsRcode(reply) != 0 || len(reply) <= len(q) {
		t.Errorf("bad reply: rcode %d, %d bytes", dnsRcode(reply), len(reply))
	}
}

// A name with an address set on the status page is answered from it at
// once: the right record kind gets the address, the wrong one a clean empty
// answer, and no name server is ever asked for either.
func TestFixedNames(t *testing.T) {
	p := &dnsPicker{
		logf: func(string, ...any) {},
		plainAsk: func(ctx context.Context, _, _ string, q []byte) ([]byte, error) {
			t.Error("a fixed name must not reach a plain server")
			return nil, errors.New("must not be asked")
		},
		dohAsk: func(ctx context.Context, q []byte) ([]byte, error) {
			t.Error("a fixed name must not go over HTTPS")
			return nil, errors.New("must not be asked")
		},
	}
	p.setFixedNames(map[string]string{"Headscale.Example.Com.": "203.0.113.9"})

	q := dnsQuery(9, "headscale.example.com")
	r := p.forwardQuery(context.Background(), "udp", "1.1.1.1:53", q)
	if dnsRcode(r) != 0 || dnsAnswerCount(r) != 1 {
		t.Fatalf("fixed A answer: rcode %d, %d answers", dnsRcode(r), dnsAnswerCount(r))
	}
	var pr dnsmessage.Parser
	if _, err := pr.Start(r); err != nil {
		t.Fatalf("reply does not parse: %v", err)
	}
	if _, err := pr.AllQuestions(); err != nil {
		t.Fatalf("reply question: %v", err)
	}
	if _, err := pr.AnswerHeader(); err != nil {
		t.Fatalf("reply answer header: %v", err)
	}
	a, err := pr.AResource()
	if err != nil {
		t.Fatalf("reply A record: %v", err)
	}
	if got, want := netip.AddrFrom4(a.A), netip.MustParseAddr("203.0.113.9"); got != want {
		t.Errorf("answered %v, want %v", got, want)
	}

	// The record kind with no address set: a clean empty answer, so Go's
	// resolver finds the name and stops asking. (The tail of a query is
	// qtype then qclass; the AAAA type goes at len-4.)
	q6 := append([]byte(nil), dnsQuery(9, "headscale.example.com")...)
	q6[len(q6)-4], q6[len(q6)-3] = 0, 28 // AAAA
	r6 := p.forwardQuery(context.Background(), "udp", "1.1.1.1:53", q6)
	if dnsRcode(r6) != 0 || dnsAnswerCount(r6) != 0 {
		t.Errorf("AAAA for an IPv4-only fixed name: rcode %d, %d answers", dnsRcode(r6), dnsAnswerCount(r6))
	}

	// A name that is not fixed takes the ordinary path (plain, then HTTPS).
	p.plainAsk = func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return noAnswerTo(q), nil }
	p.dohAsk = func(ctx context.Context, q []byte) ([]byte, error) {
		r := replyTo(q, 0)
		r[11] = 0xAA
		return r, nil
	}
	if r := p.forwardQuery(context.Background(), "udp", "1.1.1.1:53", dnsQuery(9, "other.example")); r[11] != 0xAA {
		t.Error("an unfixed name did not take the ordinary path")
	}
}

// Every endpoint is asked at once: one that answers quickly wins over
// endpoints that would take longer than the resolver's patience, and when
// none can answer the failures are reported together.
func TestDoHRace(t *testing.T) {
	q := dnsQuery(1, "example.com")
	_, qs, _ := dnsParseQuery(q)
	good := dnsBuildReply(q, qs, []netip.Addr{netip.MustParseAddr("203.0.113.9")})
	eps := []dohEndpoint{
		{"slow-a.doh.example", "/dns-query", []string{"1.1.1.1", "1.0.0.1"}},
		{"slow-b.doh.example", "/dns-query", []string{"8.8.8.8"}},
		{"fast.doh.example", "/dns-query", []string{"8.8.4.4"}},
	}
	start := time.Now()
	reply, err := dohRace(context.Background(), q, eps,
		func(ctx context.Context, host, path, ip string, query []byte) ([]byte, error) {
			if host == "fast.doh.example" {
				time.Sleep(20 * time.Millisecond)
				return good, nil
			}
			time.Sleep(2 * time.Second) // would miss any sane deadline
			return nil, errors.New("no route")
		})
	if err != nil {
		t.Fatalf("race: %v", err)
	}
	if dnsAnswerCount(reply) != 1 {
		t.Errorf("race returned a reply with %d answers", dnsAnswerCount(reply))
	}
	if time.Since(start) > time.Second {
		t.Errorf("the race took %v; endpoints were not asked at once", time.Since(start))
	}

	_, err = dohRace(context.Background(), q, eps,
		func(ctx context.Context, host, path, ip string, query []byte) ([]byte, error) {
			return nil, errors.New("no route to " + ip)
		})
	if err == nil || !strings.Contains(err.Error(), "8.8.4.4") || !strings.Contains(err.Error(), "1.1.1.1") {
		t.Errorf("all failing should report every endpoint: %v", err)
	}
}

// An endpoint that hands back something that is not an answer — an
// interceptor's page over port 443, a refusal, an empty answer, another
// name's answer — counts as failing, not as an answer.
func TestAnswerProblems(t *testing.T) {
	q := dnsQuery(1, "example.com")
	_, qs, _ := dnsParseQuery(q)
	good := dnsBuildReply(q, qs, []netip.Addr{netip.MustParseAddr("203.0.113.9")})
	other := dnsQuery(1, "other.example")
	_, qsOther, _ := dnsParseQuery(other)
	servfail := dnsBuildReply(q, qs, nil)
	servfail[3] |= 0x02
	otherAnswer := dnsBuildReply(other, qsOther, []netip.Addr{netip.MustParseAddr("203.0.113.9")})
	for name, tt := range map[string]struct {
		reply []byte
		want  bool // true = a problem
	}{
		"a real answer":    {good, false},
		"an error page":    {[]byte("<html>403 forbidden</html>"), true},
		"a refusal":        {servfail, true},
		"an empty answer":  {dnsBuildReply(q, qs, nil), true},
		"another name":     {otherAnswer, true},
		"the query itself": {q, true},
	} {
		if err := dnsAnswerProblems(q, tt.reply, "doh.example"); (err != nil) != tt.want {
			t.Errorf("%s: err = %v, want problem = %v", name, err, tt.want)
		}
	}
}

// install must wire the picker into every place a lookup can come from.
// Tailscale's control client does not read net.DefaultResolver: it copies
// the DNS cache's forwarder (dnscache.Get().Forward) when it is built.
// A fork that replaced only the default resolver left coordination-server
// lookups on the plain path, which is why a Headscale name fell through to
// the DERP bootstrap DNS that cannot know it.
func TestInstallWiresBothResolvers(t *testing.T) {
	oldDefault := net.DefaultResolver
	oldForward := dnscache.Get().Forward
	defer func() {
		net.DefaultResolver = oldDefault
		dnscache.Get().Forward = oldForward
	}()

	p := &dnsPicker{
		logf:     func(string, ...any) {},
		plainAsk: func(ctx context.Context, _, _ string, q []byte) ([]byte, error) { return replyTo(q, 0), nil },
	}
	p.install()

	if net.DefaultResolver == oldDefault {
		t.Error("install did not replace the default resolver")
	}
	if dnscache.Get().Forward == nil {
		t.Fatal("install did not set the DNS cache forwarder")
	}
	if dnscache.Get().Forward != net.DefaultResolver {
		t.Error("control-client lookups and daemon lookups use different resolvers")
	}
}
