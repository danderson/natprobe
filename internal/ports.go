package internal

// Ports are the default ports that both client and server use for probing.
var Ports = []int{
	// One more random port in the IANA "Dynamic Ports"
	// range. Along with the other ports below, we cover each
	// of the 3 IANA port ranges ("Well Known", "Registered",
	// "Dynamic") with at least 2 ports each.
	60000,

	// QUIC, likely to be open even on restrictive
	// networks. These are also two ports in the IANA "Well
	// Known Ports" range.
	80, 443,

	// VPN protocols. Likely to be open on restrictive, but
	// business-friendly networks.

	// IKE (IPSec)
	500,
	// L2TP over UDP
	1701,
	// IPSec ESP over UDP
	4500,
	// PPTP
	1723,
	// OpenVPN
	1194,
	// Wireguard
	51820,

	// VOIP protocols. Likely to be open on restrictive, but
	// business-friendly networks.

	// STUN
	3478,
	// SIP cleartext
	5060,
	// SIP TLS
	5061,
}
