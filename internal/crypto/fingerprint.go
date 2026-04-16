package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
)

// Fingerprint computes a stable identifier for an IP + ASN combination.
// IPv4: masks to /24, IPv6: masks to /48, then SHA256(subnet + asn), returns first 16 bytes as hex.
func Fingerprint(ip net.IP, asn uint) string {
	var subnet net.IP
	if ip4 := ip.To4(); ip4 != nil {
		subnet = ip4.Mask(net.CIDRMask(24, 32))
	} else {
		subnet = ip.Mask(net.CIDRMask(48, 128))
	}

	h := sha256.Sum256(append(subnet, []byte(fmt.Sprint(asn))...))
	return hex.EncodeToString(h[:16])
}

// ParseIP parses a string IP address. Returns nil if the string is invalid.
func ParseIP(s string) net.IP {
	return net.ParseIP(s)
}

// FingerprintIP is a string-based convenience wrapper around Fingerprint.
// ipStr is a dotted-decimal or colon-hex IP address string.
// asnStr may be an ASN in "AS12345" format, a plain number string, or empty.
// Returns the fingerprint hex string and an error if the IP cannot be parsed.
func FingerprintIP(ipStr, asnStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("FingerprintIP: invalid IP address %q", ipStr)
	}

	var asn uint
	if asnStr != "" {
		s := asnStr
		// Strip "AS" prefix if present
		if len(s) > 2 && (s[:2] == "AS" || s[:2] == "as") {
			s = s[2:]
		}
		var n uint64
		if _, err := fmt.Sscan(s, &n); err == nil {
			asn = uint(n)
		}
	}

	return Fingerprint(ip, asn), nil
}
