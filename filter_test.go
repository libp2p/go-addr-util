package addrutil

import (
	"testing"

	ma "github.com/multiformats/go-multiaddr"
)

func TestSubtractAndNegFilter(t *testing.T) {
	localhost := newMultiaddr(t, "/ip4/127.0.0.1/tcp/1234")
	private := newMultiaddr(t, "/ip4/192.168.1.1/tcp/1234")
	toRemoveFilter := SubtractFilter(
		localhost,
		newMultiaddr(t, "/ip6/::1/tcp/1234"),
		newMultiaddr(t, "/ip4/1.2.3.4/udp/1234/utp"),
	)
	result := FilterAddrs([]ma.Multiaddr{localhost, private}, toRemoveFilter)
	if len(result) != 1 || !result[0].Equal(private) {
		t.Errorf("Expected only one remaining address: %s", private.String())
	}

	// Negate original filter
	result = FilterAddrs([]ma.Multiaddr{localhost, private}, FilterNeg(toRemoveFilter))
	if len(result) != 1 || !result[0].Equal(localhost) {
		t.Errorf("Expected only one remaining address: %s", localhost.String())
	}
}

func TestIsFDCostlyTransport(t *testing.T) {
	tcpMa := newMultiaddr(t, "/ip4/127.0.0.1/tcp/1234")
	if ok := IsFDCostlyTransport(tcpMa); !ok {
		t.Errorf("Expected address %s to need a new file descriptor per new connection", tcpMa.String())
	}
	udpMa := newMultiaddr(t, "/ip4/127.0.0.1/udp/1234")
	if ok := IsFDCostlyTransport(udpMa); ok {
		t.Errorf("Expected address %s to not need a new file descriptor per new connection", udpMa.String())
	}
}

func TestIsFDCostly(t *testing.T) {
	good := []ma.Multiaddr{
		newMultiaddr(t, "/ip4/127.0.0.1/tcp/1234"),
		newMultiaddr(t, "/ip4/0.0.0.0/tcp/1234"),
		newMultiaddr(t, "/ip6/::1/tcp/1234"),
		newMultiaddr(t, "/ip6/::/tcp/1234"),
		newMultiaddr(t, "/ip6/fe80::1/tcp/1234"),
		newMultiaddr(t, "/ip6/fe80::/tcp/1234"),
		newMultiaddr(t, "/ip6/fe80::/tcp/1234/http"),
		newMultiaddr(t, "/ip4/127.0.0.1/tcp/1234/http"),
	}

	bad := []ma.Multiaddr{
		newMultiaddr(t, "/ip4/127.0.0.1/udp/1234"),
		newMultiaddr(t, "/ip4/0.0.0.0/udp/1234/utp"),
		newMultiaddr(t, "/ip6/::1/udp/1234"),
		newMultiaddr(t, "/ip6/::/udp/1234"),
	}

	for _, a := range bad {
		if IsFDCostlyTransport(a) {
			t.Errorf("addr %s should not be fd costly", a)
		}
	}

	for _, a := range good {
		if !IsFDCostlyTransport(a) {
			t.Errorf("addr %s should be fd costly", a)
		}
	}
}

func TestIsFdCostlyMalformed(t *testing.T) {
	bad := []ma.Multiaddr{
		newMultiaddr(t, "/ip4/127.0.0.1/"),
		newMultiaddr(t, "/ip4/0.0.0.0/"),
		newMultiaddr(t, "/ip6/::1/"),
		newMultiaddr(t, "/ip6/::/"),
	}

	for _, a := range bad {
		if IsFDCostlyTransport(a) {
			t.Errorf("addr %s should not be fd costly", a)
		}
	}
}
