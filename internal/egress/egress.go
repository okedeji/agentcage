// Package egress is the in-run HTTP CONNECT proxy: a cage reaches only the
// hosts its EGRESS allow: policy names, and the internal run network makes
// this the only way out. It filters on the CONNECT host without terminating
// TLS, so it holds no secret and never sees a payload.
package egress

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// Config maps a source (a cage's run-network address) to the hostnames it may
// reach. Default deny: an unknown source or unlisted host is refused. Names
// maps a source address to a human label (the agent's name) for event lines.
// Observe flips the proxy to audit mode: every host is allowed and recorded,
// so the operator can learn a server's egress profile before locking it down.
type Config struct {
	Sources map[string][]string `json:"sources"`
	Names   map[string]string   `json:"names,omitempty"`
	Observe bool                `json:"observe,omitempty"`
}

// Handler returns the CONNECT proxy; allow sets are compiled once at boot. It
// writes one line to events per (agent, host, decision) the first time it sees
// it: a denial in normal mode, or an observation in audit mode.
func Handler(cfg Config, events io.Writer) http.Handler {
	allow := make(map[string]map[string]bool, len(cfg.Sources))
	for src, hosts := range cfg.Sources {
		set := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			set[h] = true
		}
		allow[src] = set
	}

	var mu sync.Mutex
	logged := map[string]bool{}
	logOnce := func(kind, src, host string) {
		if events == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		key := kind + " " + src + " " + host
		if logged[key] {
			return
		}
		logged[key] = true
		name := cfg.Names[src]
		if name == "" {
			name = src
		}
		switch kind {
		case "observed":
			// Audit mode: a machine-readable marker the CLI collects into an
			// EGRESS line, plus the agent for a multi-cage run.
			_, _ = fmt.Fprintf(events, "egress observed: %s (agent %s)\n", host, name)
		default:
			// Lead with the fast path (allow for one run), then the permanent
			// one (bake it into the Vesselfile and rebuild).
			_, _ = fmt.Fprintf(events, "egress denied: %s (agent %s) — allow it with 'mcpvessel run/serve --egress %s', or bake it in with EGRESS allow:%s and a rebuild\n", host, name, host, host)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "egress proxy only supports CONNECT", http.StatusMethodNotAllowed)
			return
		}
		host := hostOnly(r.Host)
		src := hostOnly(r.RemoteAddr)
		// Audit mode allows every host and records it; normal mode denies
		// anything the source's allow list does not name.
		if cfg.Observe {
			logOnce("observed", src, host)
		} else if !allow[src][host] {
			logOnce("denied", src, host)
			http.Error(w, "egress to "+host+" not allowed", http.StatusForbidden)
			return
		}
		tunnel(w, r.Host)
	})
}

// tunnel dials the target and copies bytes both ways until either side
// closes. It joins its two copy goroutines before returning; none outlives
// the request.
func tunnel(w http.ResponseWriter, target string) {
	upstream, err := dialTarget(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "egress proxy needs a hijackable connection", http.StatusInternalServerError)
		_ = upstream.Close()
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(&wg, upstream, client)
	go pipe(&wg, client, upstream)
	wg.Wait()
	_ = upstream.Close()
	_ = client.Close()
}

// dialTarget is a var so tests can tunnel to a loopback backend that
// dialPublic would correctly refuse. Production always uses dialPublic.
var dialTarget = dialPublic

// dialPublic resolves the host and dials only a public address, refusing
// private, loopback, and link-local ones. Without this, an allowed hostname
// resolving to an internal IP (directly or via DNS rebinding) is an SSRF
// pivot into a sibling cage, a gateway, or the host. It dials the address it
// checked, never re-resolving, so a name cannot rebind between check and
// dial.
func dialPublic(target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("malformed egress target %q", target)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolving egress host %s", host)
	}
	for _, ip := range ips {
		if isPublic(ip) {
			return net.Dial("tcp", net.JoinHostPort(ip.String(), port))
		}
	}
	return nil, fmt.Errorf("egress host %s resolves to no public address", host)
}

func isPublic(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast()
}

func pipe(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
