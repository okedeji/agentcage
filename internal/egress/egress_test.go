package egress

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testHandler builds the proxy with no event sink; tests that assert on
// denial lines call Handler directly with a buffer.
func testHandler(cfg Config) http.Handler { return Handler(cfg, nil) }

// connect sends a raw CONNECT for target and returns the status line plus the
// source IP the proxy saw, so a test can allow or deny exactly it.
func connect(t *testing.T, proxyAddr, target string) (status string, srcIP string, conn net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	srcIP = c.LocalAddr().(*net.TCPAddr).IP.String()
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading status: %v", err)
	}
	return line, srcIP, c
}

func TestHandler_RefusesUnknownSource(t *testing.T) {
	srv := httptest.NewServer(testHandler(Config{Sources: map[string][]string{}}))
	defer srv.Close()
	status, _, c := connect(t, srv.Listener.Addr().String(), "example.com:443")
	_ = c.Close()
	if !contains(status, "403") {
		t.Errorf("unknown source status = %q, want 403", status)
	}
}

func TestHandler_LogsDenialOncePerHost(t *testing.T) {
	// Learn the source IP, then deny it everything and watch the event sink.
	tmp := httptest.NewServer(testHandler(Config{}))
	_, srcIP, c0 := connect(t, tmp.Listener.Addr().String(), "x:1")
	_ = c0.Close()
	tmp.Close()

	var events bytes.Buffer
	cfg := Config{Sources: map[string][]string{srcIP: {}}, Names: map[string]string{srcIP: "github"}}
	srv := httptest.NewServer(Handler(cfg, &events))
	defer srv.Close()

	// Two denials of the same host should log exactly one line.
	for i := 0; i < 2; i++ {
		_, _, c := connect(t, srv.Listener.Addr().String(), "objects.githubusercontent.com:443")
		_ = c.Close()
	}
	got := events.String()
	if strings.Count(got, "egress denied:") != 1 {
		t.Errorf("want one deduped denial line, got:\n%s", got)
	}
	if !strings.Contains(got, "objects.githubusercontent.com") || !strings.Contains(got, "agent github") {
		t.Errorf("denial line missing host or agent name:\n%s", got)
	}
	// Lead with the fast runtime override, then the permanent bake-in.
	if !strings.Contains(got, "--egress") || !strings.Contains(got, "EGRESS allow:") {
		t.Errorf("denial line should offer both --egress and the EGRESS bake-in:\n%s", got)
	}
}

func TestHandler_ObserveRecordsInsteadOfDenying(t *testing.T) {
	// Learn the source IP, then run in audit mode with no allow list at all.
	tmp := httptest.NewServer(testHandler(Config{}))
	_, srcIP, c0 := connect(t, tmp.Listener.Addr().String(), "x:1")
	_ = c0.Close()
	tmp.Close()

	var events bytes.Buffer
	cfg := Config{Observe: true, Names: map[string]string{srcIP: "fetch"}}
	srv := httptest.NewServer(Handler(cfg, &events))
	defer srv.Close()

	// The host is recorded even though nothing allows it; the tunnel then fails
	// to dial, but the observation is written before that.
	for i := 0; i < 2; i++ {
		_, _, c := connect(t, srv.Listener.Addr().String(), "api.github.com:443")
		_ = c.Close()
	}
	got := events.String()
	if strings.Count(got, "egress observed:") != 1 {
		t.Errorf("want one deduped observation, got:\n%s", got)
	}
	if !strings.Contains(got, "api.github.com") || !strings.Contains(got, "agent fetch") {
		t.Errorf("observation missing host or agent:\n%s", got)
	}
	if strings.Contains(got, "denied") {
		t.Errorf("audit mode must not deny:\n%s", got)
	}
}

func TestHandler_RefusesDisallowedHost(t *testing.T) {
	// Learn the source IP from a throwaway connect, then allow only good.test.
	tmp := httptest.NewServer(testHandler(Config{}))
	_, srcIP, c0 := connect(t, tmp.Listener.Addr().String(), "x:1")
	_ = c0.Close()
	tmp.Close()

	real := httptest.NewServer(testHandler(Config{Sources: map[string][]string{srcIP: {"good.test"}}}))
	defer real.Close()
	status, _, c := connect(t, real.Listener.Addr().String(), "bad.test:443")
	_ = c.Close()
	if !contains(status, "403") {
		t.Errorf("disallowed host status = %q, want 403", status)
	}
}

func TestHandler_TunnelsAllowedHost(t *testing.T) {
	// The backend is on loopback, which the SSRF guard rightly refuses;
	// swap in a permissive dialer to exercise the data path.
	old := dialTarget
	dialTarget = func(target string) (net.Conn, error) { return net.Dial("tcp", target) }
	defer func() { dialTarget = old }()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		_, _ = conn.Write([]byte("echo:" + line))
	}()

	backendHost := hostOnly(backend.Addr().String())

	probe := httptest.NewServer(testHandler(Config{}))
	_, srcIP, p := connect(t, probe.Listener.Addr().String(), "x:1")
	_ = p.Close()
	probe.Close()

	srv := httptest.NewServer(testHandler(Config{Sources: map[string][]string{srcIP: {backendHost}}}))
	defer srv.Close()

	status, _, c := connect(t, srv.Listener.Addr().String(), backend.Addr().String())
	defer func() { _ = c.Close() }()
	if !contains(status, "200") {
		t.Fatalf("tunnel status = %q, want 200", status)
	}
	_, _ = fmt.Fprint(c, "ping\n")
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading tunneled reply: %v", err)
	}
	if reply != "echo:ping\n" {
		t.Errorf("tunneled reply = %q, want echo:ping", reply)
	}
}

func TestHandler_RefusesPrivateTarget(t *testing.T) {
	// The host is explicitly allowed, so a 403 can only come from the dial
	// guard refusing the private address, not from host-deny.
	tmp := httptest.NewServer(testHandler(Config{}))
	_, srcIP, c0 := connect(t, tmp.Listener.Addr().String(), "x:1")
	_ = c0.Close()
	tmp.Close()

	srv := httptest.NewServer(testHandler(Config{Sources: map[string][]string{srcIP: {"10.0.0.1"}}}))
	defer srv.Close()
	status, _, c := connect(t, srv.Listener.Addr().String(), "10.0.0.1:8080")
	_ = c.Close()
	if !contains(status, "403") {
		t.Errorf("private target status = %q, want 403 (SSRF guard)", status)
	}
}

func TestIsPublic(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"10.0.0.1", false},            // RFC1918
		{"192.168.5.2", false},         // RFC1918 (the Lima host)
		{"172.16.0.1", false},          // RFC1918
		{"127.0.0.1", false},           // loopback
		{"169.254.169.254", false},     // link-local (cloud metadata)
		{"0.0.0.0", false},             // unspecified
		{"::1", false},                 // IPv6 loopback
		{"fd00::1", false},             // IPv6 ULA
		{"2606:4700:4700::1111", true}, // public IPv6
	}
	for _, c := range cases {
		if got := isPublic(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isPublic(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestHandler_RejectsNonConnect(t *testing.T) {
	srv := httptest.NewServer(testHandler(Config{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", resp.StatusCode)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
