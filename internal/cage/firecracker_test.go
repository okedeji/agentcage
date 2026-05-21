package cage

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each allocateIPPair must return a host/guest pair that satisfies the
// Linux kernel's ic_setup_routes check `(client ^ gateway) & netmask == 0`.
// The earlier allocator handed out sequential IPs treated as /30, which
// drifted into invalid pairs by the 4th cage: host=.7 (broadcast), guest
// in next /30 → kernel rejected the default route and the cage saw
// ENETUNREACH on every connect. /31 + pair allocation makes the check a
// tautology for all slots.
func TestAllocateIPPair_PairsAreValid(t *testing.T) {
	resetIPCounter(t)
	p := &FirecrackerProvisioner{}
	seen := map[string]struct{}{}

	for i := 0; i < 100; i++ {
		hostIP, guestIP, err := p.allocateIPPair()
		require.NoError(t, err)

		host := net.ParseIP(hostIP).To4()
		guest := net.ParseIP(guestIP).To4()
		require.NotNil(t, host, "slot %d: host %q is not IPv4", i, hostIP)
		require.NotNil(t, guest, "slot %d: guest %q is not IPv4", i, guestIP)

		// /31 mask: only the last bit may differ. (host ^ guest) & 0xFE must be 0.
		assert.Zero(t, (host[3]^guest[3])&0xFE,
			"slot %d: host %s and guest %s straddle /31 boundary", i, hostIP, guestIP)
		assert.Equal(t, host[2], guest[2],
			"slot %d: third octet mismatch (%s vs %s)", i, hostIP, guestIP)

		// Host must be on the even side of the /31 so guest = host + 1
		// always fits without byte wraparound at .255.
		assert.Zero(t, host[3]&0x01,
			"slot %d: host %s last octet must be even for /31 alignment", i, hostIP)

		assert.NotContains(t, seen, hostIP, "slot %d: host IP collision %s", i, hostIP)
		assert.NotContains(t, seen, guestIP, "slot %d: guest IP collision %s", i, guestIP)
		seen[hostIP] = struct{}{}
		seen[guestIP] = struct{}{}
	}
}

func TestAllocateIPPair_Exhaustion(t *testing.T) {
	resetIPCounter(t)
	ipMu.Lock()
	ipCounter = ipMaxSlots
	ipMu.Unlock()

	p := &FirecrackerProvisioner{}
	_, _, err := p.allocateIPPair()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

// resetIPCounter rewinds the package-global allocator so tests that
// run after a real boot (or each other) see a clean slate. The counter
// is process-global by design; tests get the reset via t.Cleanup.
func resetIPCounter(t *testing.T) {
	t.Helper()
	ipMu.Lock()
	prev := ipCounter
	ipCounter = 0
	ipMu.Unlock()
	t.Cleanup(func() {
		ipMu.Lock()
		ipCounter = prev
		ipMu.Unlock()
	})
}
