package gcdns

// DefaultRootTargets returns the built-in DNS root bootstrap set used by
// Beacon Resolver iterative recursion. The addresses mirror the IANA root
// server registry reviewed on 2026-08-21. Each address is represented as an
// independent target so scheduler health and latency accounting remain
// address-specific. Operators may replace this set through runtime
// configuration when a controlled root-hints lifecycle is introduced.
func DefaultRootTargets() []ResolverTarget {
	return []ResolverTarget{
		{ID: "a.root-servers.net/ipv4", Address: "198.41.0.4:53", Network: resolverNetworkUDP},
		{ID: "a.root-servers.net/ipv6", Address: "[2001:503:ba3e::2:30]:53", Network: resolverNetworkUDP},
		{ID: "b.root-servers.net/ipv4", Address: "170.247.170.2:53", Network: resolverNetworkUDP},
		{ID: "b.root-servers.net/ipv6", Address: "[2801:1b8:10::b]:53", Network: resolverNetworkUDP},
		{ID: "c.root-servers.net/ipv4", Address: "192.33.4.12:53", Network: resolverNetworkUDP},
		{ID: "c.root-servers.net/ipv6", Address: "[2001:500:2::c]:53", Network: resolverNetworkUDP},
		{ID: "d.root-servers.net/ipv4", Address: "199.7.91.13:53", Network: resolverNetworkUDP},
		{ID: "d.root-servers.net/ipv6", Address: "[2001:500:2d::d]:53", Network: resolverNetworkUDP},
		{ID: "e.root-servers.net/ipv4", Address: "192.203.230.10:53", Network: resolverNetworkUDP},
		{ID: "e.root-servers.net/ipv6", Address: "[2001:500:a8::e]:53", Network: resolverNetworkUDP},
		{ID: "f.root-servers.net/ipv4", Address: "192.5.5.241:53", Network: resolverNetworkUDP},
		{ID: "f.root-servers.net/ipv6", Address: "[2001:500:2f::f]:53", Network: resolverNetworkUDP},
		{ID: "g.root-servers.net/ipv4", Address: "192.112.36.4:53", Network: resolverNetworkUDP},
		{ID: "g.root-servers.net/ipv6", Address: "[2001:500:12::d0d]:53", Network: resolverNetworkUDP},
		{ID: "h.root-servers.net/ipv4", Address: "198.97.190.53:53", Network: resolverNetworkUDP},
		{ID: "h.root-servers.net/ipv6", Address: "[2001:500:1::53]:53", Network: resolverNetworkUDP},
		{ID: "i.root-servers.net/ipv4", Address: "192.36.148.17:53", Network: resolverNetworkUDP},
		{ID: "i.root-servers.net/ipv6", Address: "[2001:7fe::53]:53", Network: resolverNetworkUDP},
		{ID: "j.root-servers.net/ipv4", Address: "192.58.128.30:53", Network: resolverNetworkUDP},
		{ID: "j.root-servers.net/ipv6", Address: "[2001:503:c27::2:30]:53", Network: resolverNetworkUDP},
		{ID: "k.root-servers.net/ipv4", Address: "193.0.14.129:53", Network: resolverNetworkUDP},
		{ID: "k.root-servers.net/ipv6", Address: "[2001:7fd::1]:53", Network: resolverNetworkUDP},
		{ID: "l.root-servers.net/ipv4", Address: "199.7.83.42:53", Network: resolverNetworkUDP},
		{ID: "l.root-servers.net/ipv6", Address: "[2001:500:9f::42]:53", Network: resolverNetworkUDP},
		{ID: "m.root-servers.net/ipv4", Address: "202.12.27.33:53", Network: resolverNetworkUDP},
		{ID: "m.root-servers.net/ipv6", Address: "[2001:dc3::35]:53", Network: resolverNetworkUDP},
	}
}
