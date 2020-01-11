natprobe is a Go toolkit to probe the behavior of NAT devices. It includes:

 - [`go.universe.tf/natprobe/client`](https://godoc.org/go.universe.tf/natprobe/client):
   a Go library to probe for the presence and behavior of a NAT
   device.
 - `go.universe.tf/natprobe/cli`: a thin CLI wrapper around the client
   library.
 - `go.universe.tf/natprobe/server`: a server that provides mapping
   information and probing services to the client library.

By default, the client talk to two courtesy servers at
`natprobe1.universe.tf` and `natprobe2.universe.tf`.

Sample output from the CLI:

```
$ ./cli
NAT allocates a new ip:port for every unique 3-tuple (protocol, source ip, source ports).
  This is best practice for NAT devices.
  This makes NAT traversal easier.
Firewall requires outbound traffic to an ip:port before allowing inbound traffic from that ip:port.
  This is common practice for NAT gateways.
  This makes NAT traversal more difficult.
NAT seems to try and make the public port number match the LAN port number.
NAT seems to only use one public IP for this client.
```
