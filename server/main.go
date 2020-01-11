package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"go.universe.tf/natprobe/internal"
)

var (
	ports = flag.String("ports", "", "UDP listener ports")
)

func main() {
	flag.Parse()
	logger := internal.NewLogger()

	server, err := newServer(logger)
	if err != nil {
		logger.Error(err, "Failed to create server")
		os.Exit(1)
	}

	server.run()
}

func newServer(logger logr.Logger) (*server, error) {
	ips, err := publicIPs()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate local public IPs: %s", err)
	}
	if len(ips) < 2 {
		return nil, errors.New("not enough public IPs to provide a useful testing server")
	}

	ports, err := parsePorts()
	if err != nil {
		return nil, fmt.Errorf("failed to parse listening ports: %s", err)
	}

	ret := &server{
		logger: logger,
	}

	for _, ip := range ips {
		for _, port := range ports {
			addr := &net.UDPAddr{IP: ip, Port: port}
			conn, err := net.ListenUDP("udp4", addr)
			if err != nil {
				return nil, fmt.Errorf("failed to listen on %s: %s", addr, err)
			}
			ret.conns = append(ret.conns, conn)
			logger.Info("Created UDP listening port", "local-addr", addr.String())
		}
	}

	return ret, nil
}

type server struct {
	conns  []*net.UDPConn
	logger logr.Logger
}

func (s *server) run() {
	for _, conn := range s.conns {
		go s.handle(conn)
	}
	s.logger.Info("Startup complete")
	select {}
}

func (s *server) handle(conn *net.UDPConn) error {
	var buf [1500]byte
	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			s.logger.Error(err, "Error reading from socket", "local-addr", conn.LocalAddr())
		}
		if n != 180 {
			s.logger.Info("Ignoring packet of unexpected length", "local-addr", conn.LocalAddr(), "remote-addr", addr, "packet-size", n)
			continue
		}

		varyAddr, varyPort := buf[0]&1 != 0, buf[0]&2 != 0
		var respConn *net.UDPConn
		for _, c := range s.conns {
			myaddr := conn.LocalAddr().(*net.UDPAddr)
			uaddr := c.LocalAddr().(*net.UDPAddr)
			if uaddr.IP.Equal(myaddr.IP) == varyAddr {
				continue
			}
			if (uaddr.Port == myaddr.Port) == varyPort {
				continue
			}
			respConn = c
			break
		}

		copy(buf[:16], addr.IP.To16())
		binary.BigEndian.PutUint16(buf[16:18], uint16(addr.Port))
		if _, err = respConn.WriteToUDP(buf[:18], addr); err != nil {
			s.logger.Error(err, "Failed to send response", "remote-addr", addr)
			continue
		}

		s.logger.Info("Provided NAT mapping", "local-addr", respConn.LocalAddr(), "remote-addr", addr, "vary-addr", varyAddr, "vary-port", varyPort)
	}
}

func publicIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ret []net.IP

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, genAddr := range addrs {
			addr, ok := genAddr.(*net.IPNet)
			if !ok || addr.IP.To4() == nil || !addr.IP.IsGlobalUnicast() || isrfc1918(addr.IP) {
				continue
			}
			ret = append(ret, addr.IP.To4())
		}
	}

	return ret, nil
}

func parsePorts() ([]int, error) {
	if *ports == "" {
		return internal.Ports, nil
	}

	ret := []int{}
	for _, port := range strings.Split(*ports, ",") {
		i, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		ret = append(ret, i)
	}
	return ret, nil
}

func isrfc1918(ip net.IP) bool {
	ip = ip.To4()
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1]&0xf0 == 16) ||
		(ip[0] == 192 && ip[1] == 168)
}
