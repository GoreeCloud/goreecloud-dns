package gcdns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type runtimeDNSEndpoint struct {
	addr netip.Addr
	port uint16
}

type routingRuntimeBoundary struct {
	listeners []runtimeDNSEndpoint
	localSet  map[netip.Addr]struct{}
}

// NewRuntimeValidatedRoutingResolver creates a routing resolver only after the
// route graph and active listener/target relationship have both passed their
// fail-closed construction checks. Production startup should use this boundary
// once the native listener runtime supplies its actual endpoint state.
//
// Delegating stub resolvers are cloned into the returned router and receive the
// same immutable listener boundary so dynamically discovered child-authority
// targets are checked before they can be queried.
func NewRuntimeValidatedRoutingResolver(defaultResolver Resolver, routes []ResolverRoute, listeners []string, localAddresses []netip.Addr) (*RoutingResolver, error) {
	router, err := NewRoutingResolver(defaultResolver, routes)
	if err != nil {
		return nil, err
	}
	boundary, err := newRoutingRuntimeBoundary(listeners, localAddresses)
	if err != nil {
		return nil, err
	}
	if err := validateRoutingTargets(boundary, router.routes); err != nil {
		return nil, err
	}
	for i := range router.routes {
		if stub, ok := router.routes[i].Resolver.(*DelegatingStubResolver); ok {
			clone := *stub
			clone.runtimeBoundary = boundary
			router.routes[i].Resolver = &clone
		}
	}
	return router, nil
}

// ValidateRoutingRuntime rejects configured routed classic-DNS targets that
// would send a query back into an active GoreeCloud DNS listener. It performs no
// DNS lookup and no interface discovery so startup behavior remains deterministic
// and testable.
func ValidateRoutingRuntime(listeners []string, localAddresses []netip.Addr, routes []ResolverRoute) error {
	boundary, err := newRoutingRuntimeBoundary(listeners, localAddresses)
	if err != nil {
		return err
	}
	return validateRoutingTargets(boundary, routes)
}

func newRoutingRuntimeBoundary(listeners []string, localAddresses []netip.Addr) (*routingRuntimeBoundary, error) {
	if len(listeners) == 0 {
		return nil, errors.New("goreecloud dns: routing runtime validation requires at least one active listener")
	}
	boundary := &routingRuntimeBoundary{
		listeners: make([]runtimeDNSEndpoint, 0, len(listeners)),
		localSet:  make(map[netip.Addr]struct{}, len(localAddresses)),
	}
	for _, listener := range listeners {
		endpoint, err := parseRuntimeDNSEndpoint(listener, true)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: invalid routing listener %q: %w", listener, err)
		}
		boundary.listeners = append(boundary.listeners, endpoint)
	}
	for _, addr := range localAddresses {
		if !addr.IsValid() {
			return nil, errors.New("goreecloud dns: routing runtime local-address snapshot contains an invalid address")
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() {
			continue
		}
		boundary.localSet[addr] = struct{}{}
	}
	return boundary, nil
}

func validateRoutingTargets(boundary *routingRuntimeBoundary, routes []ResolverRoute) error {
	for _, route := range routes {
		if route.Mode == RouteRecursive {
			continue
		}
		endpoints, err := nativeRouteTargetEndpoints(route)
		if err != nil {
			return err
		}
		for _, target := range endpoints {
			if err := boundary.validateTarget(fmt.Sprintf("resolver route %q", route.Name), target); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *routingRuntimeBoundary) validateTarget(subject, target string) error {
	if b == nil {
		return errors.New("goreecloud dns: routing runtime boundary is nil")
	}
	parsedTarget, err := parseRuntimeDNSEndpoint(target, false)
	if err != nil {
		return fmt.Errorf("goreecloud dns: %s target %q cannot pass self-target validation: %w", subject, target, err)
	}
	for _, listener := range b.listeners {
		if routingTargetHitsListener(parsedTarget, listener, b.localSet) {
			return fmt.Errorf("goreecloud dns: %s target %s points back to an active GoreeCloud DNS listener", subject, target)
		}
	}
	return nil
}

func nativeRouteTargetEndpoints(route ResolverRoute) ([]string, error) {
	switch resolver := route.Resolver.(type) {
	case *ForwardingResolver:
		return schedulerTargetNames(resolver.scheduler), nil
	case *StubResolver:
		return schedulerTargetNames(resolver.scheduler), nil
	case *DelegatingStubResolver:
		return resolver.routeTargetEndpoints(), nil
	default:
		return nil, fmt.Errorf("goreecloud dns: resolver route %q does not expose native target endpoints for runtime self-target validation", route.Name)
	}
}

func schedulerTargetNames(scheduler *TargetScheduler) []string {
	if scheduler == nil {
		return nil
	}
	names := make([]string, 0, len(scheduler.targets))
	for _, state := range scheduler.targets {
		if state != nil {
			names = append(names, state.target.Name)
		}
	}
	return names
}

func parseRuntimeDNSEndpoint(value string, allowUnspecified bool) (runtimeDNSEndpoint, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || strings.TrimSpace(host) == "" {
		return runtimeDNSEndpoint{}, errors.New("endpoint must use numeric IP host:port syntax")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return runtimeDNSEndpoint{}, errors.New("runtime self-target validation requires a numeric IP address")
	}
	addr = addr.Unmap()
	if !allowUnspecified && addr.IsUnspecified() {
		return runtimeDNSEndpoint{}, errors.New("resolver target address must not be unspecified")
	}
	portNumber, err := strconv.Atoi(portText)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return runtimeDNSEndpoint{}, errors.New("endpoint port must be between 1 and 65535")
	}
	return runtimeDNSEndpoint{addr: addr, port: uint16(portNumber)}, nil
}

func routingTargetHitsListener(target, listener runtimeDNSEndpoint, localSet map[netip.Addr]struct{}) bool {
	if target.port != listener.port {
		return false
	}
	if !listener.addr.IsUnspecified() {
		return target.addr == listener.addr
	}
	if target.addr.Is4() != listener.addr.Is4() {
		return false
	}
	if target.addr.IsLoopback() {
		return true
	}
	_, local := localSet[target.addr]
	return local
}
