package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"go.universe.tf/natprobe/internal"
)

// Options configures the probe. All zero values are replaced with
// sensible defaults.
type Options struct {
	// The addresses of probe servers to use.
	ServerAddrs []string
	// The ports to probe on the probe servers.
	Ports []int

	// How long server name resolution can take.
	ResolveDuration time.Duration

	// How long the mapping phase takes.
	MappingDuration time.Duration
	// How frequently to send mapping probe packets for each socket
	// and destination.
	MappingTransmitInterval time.Duration
	// The number of sockets to use for probing.
	MappingSockets int

	// How long the firewall probing phase takes.
	FirewallDuration time.Duration
	// How frequently to send firewal probe packets for each socket.
	FirewallTransmitInterval time.Duration
}

func (o *Options) addDefaults() {
	if len(o.ServerAddrs) == 0 {
		o.ServerAddrs = []string{"natprobe1.universe.tf.", "natprobe2.universe.tf."}
	}
	if len(o.Ports) == 0 {
		o.Ports = internal.Ports
	}
	if o.ResolveDuration == 0 {
		o.ResolveDuration = 3 * time.Second
	}
	if o.MappingDuration == 0 {
		o.MappingDuration = 3 * time.Second
	}
	if o.MappingTransmitInterval == 0 {
		o.MappingTransmitInterval = 200 * time.Millisecond
	}
	if o.MappingSockets == 0 {
		o.MappingSockets = 3
	}
	if o.FirewallDuration == 0 {
		o.FirewallDuration = 3 * time.Second
	}
	if o.FirewallTransmitInterval == 0 {
		o.FirewallTransmitInterval = 50 * time.Millisecond
	}
}

// Probe probes the NAT behavior between the local machine and remote probe servers.
func Probe(ctx context.Context, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{}
	}
	opts.addDefaults()

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("enumerating local addresses: %s", err)
	}
	var localIPs []net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				localIPs = append(localIPs, ipnet.IP)
			}
		}
	}

	// Assemble destination UDP addresses.
	ips, err := resolveServerAddrs(ctx, opts.ServerAddrs, opts.ResolveDuration)
	if err != nil {
		return nil, err
	}
	dests := dests(ips, opts.Ports)

	// Channel for the mapping probe to pass a working server to the firewall.
	var (
		workingAddr  = make(chan *net.UDPAddr, 1)
		firewallDone = make(chan error)
		firewall     *FirewallProbe
	)

	// If we get any successful mapping response, use that address for
	// firewall probing.
	go func() {
		fw, err := probeFirewall(ctx, workingAddr, opts.FirewallDuration, opts.FirewallTransmitInterval)
		firewall = fw
		firewallDone <- err
	}()

	// Probe the NAT for its mapping behavior.
	probes, err := probeMapping(ctx, dests, opts.MappingSockets, opts.MappingDuration, opts.MappingTransmitInterval, workingAddr)
	if err != nil {
		return nil, err
	}

	if err = <-firewallDone; err != nil {
		return nil, err
	}

	return &Result{
		LocalIPs:       localIPs,
		MappingProbes:  probes,
		FirewallProbes: firewall,
	}, nil
}

func dests(ips []net.IP, ports []int) []*net.UDPAddr {
	var ret []*net.UDPAddr
	for _, ip := range ips {
		for _, port := range ports {
			ret = append(ret, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	return ret
}

func probeFirewall(ctx context.Context, workingAddr chan *net.UDPAddr, duration time.Duration, txInterval time.Duration) (*FirewallProbe, error) {
	dest := <-workingAddr
	if dest == nil {
		return nil, fmt.Errorf("no working server addresses available for firewall probing")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		panic("deadline unexpectedly not set in context")
	}
	if err = conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	go transmit(ctx, conn, []*net.UDPAddr{dest}, txInterval, true)

	var (
		ret = FirewallProbe{
			Local:  copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
			Remote: copyUDPAddr(dest),
		}
		buf  [1500]byte
		seen = map[string]bool{}
	)
	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return &ret, nil
			}
			return nil, err
		}

		if n != 18 {
			continue
		}

		if !seen[addr.String()] {
			ret.Received = append(ret.Received, addr)
			seen[addr.String()] = true
		}
	}
}

func probeMapping(ctx context.Context, dests []*net.UDPAddr, sockets int, duration time.Duration, txInterval time.Duration, workingAddr chan *net.UDPAddr) ([]*MappingProbe, error) {
	defer close(workingAddr)

	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	type result struct {
		probes []*MappingProbe
		err    error
	}

	done := make(chan result)

	for i := 0; i < sockets; i++ {
		go func() {
			res, err := probeOneMapping(ctx, dests, txInterval, workingAddr)
			done <- result{probes: res, err: err}
		}()
	}

	var ret []*MappingProbe
	for i := 0; i < sockets; i++ {
		res := <-done
		if res.err != nil {
			return nil, res.err
		}
		ret = append(ret, res.probes...)
	}

	return ret, nil
}

func probeOneMapping(ctx context.Context, dests []*net.UDPAddr, txInterval time.Duration, workingAddr chan *net.UDPAddr) ([]*MappingProbe, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}

	var (
		seenByDest = map[string]bool{}
		ret        = []*MappingProbe{}
	)

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		conn.Close()

		for _, dest := range dests {
			if !seenByDest[dest.String()] {
				ret = append(ret, &MappingProbe{
					Local:   copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
					Remote:  copyUDPAddr(dest),
					Timeout: true,
				})
			}
		}
	}()

	deadline, ok := ctx.Deadline()
	if !ok {
		panic("deadline unexpectedly not set in context")
	}
	if err = conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	go transmit(ctx, conn, dests, txInterval, false)

	var (
		buf  [1500]byte
		seen = map[string]bool{}
	)

	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return ret, nil
			}
			return nil, err
		}

		if n != 18 {
			continue
		}

		mapped := &net.UDPAddr{
			IP:   net.IP(buf[:16]),
			Port: int(binary.BigEndian.Uint16(buf[16:18])),
		}

		probe := &MappingProbe{
			Local:  copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
			Mapped: copyUDPAddr(mapped),
			Remote: copyUDPAddr(addr),
		}
		if !seen[probe.key()] {
			ret = append(ret, probe)
			seen[probe.key()] = true
			seenByDest[addr.String()] = true
			select {
			case workingAddr <- copyUDPAddr(addr):
			default:
			}
		}
	}
}

func transmit(ctx context.Context, conn *net.UDPConn, dests []*net.UDPAddr, txInterval time.Duration, cycle bool) {
	var req [180]byte
	done := make(chan struct{})
	for _, dest := range dests {
		go func(dest *net.UDPAddr) {
			defer func() { done <- struct{}{} }()

			for {
				if cycle {
					req[0] = (req[0] + 1) % 4
				}
				if _, err := conn.WriteToUDP(req[:], dest); err != nil {
					// TODO: log, somehow...
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(txInterval):
				}
			}
		}(dest)
	}

	for range dests {
		<-done
	}
}

func resolveServerAddrs(ctx context.Context, addrs []string, timeout time.Duration) (ips []net.IP, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, addr := range addrs {
		results, err := net.DefaultResolver.LookupIPAddr(ctx, addr)
		if err != nil {
			return nil, err
		}

		for _, result := range results {
			ip := result.IP.To4()
			if ip == nil {
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func copyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), a.IP...),
		Port: a.Port,
	}
}
